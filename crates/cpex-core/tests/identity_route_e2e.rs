// Location: ./crates/cpex-core/tests/identity_route_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end tests for the route-level `identity:` block (Slice A).
//
// Verifies the hook-specific binding semantics:
//   * A route's `identity:` block is the authoritative dispatch list
//     for the `identity.resolve` hook on that route.
//   * The route's `plugins:` block (which means "per-route overrides"
//     in APL-driven routes, "per-route binding" otherwise) does NOT
//     bind plugins for the `identity.resolve` hook.
//   * Dispatch order matches the order steps are declared in
//     `identity:`, NOT the plugins' chain-priority values.
//   * Per-step config overrides flow through the existing
//     `create_override_instance` pathway.
//
// Companion tests for IdentityHook *semantics* (payload threading,
// rejection, apply_to_extensions) live in `identity_e2e.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use cpex_core::config;
use cpex_core::context::PluginContext;
use cpex_core::extensions::{MetaExtension, SubjectExtension};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource, HOOK_IDENTITY_RESOLVE};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

// =====================================================================
// Test plugin: a recording identity resolver
// =====================================================================
//
// Each instance writes its own name to a shared `Vec<String>` ledger
// when invoked. That lets tests assert (a) which plugins fired and
// (b) in what order. Also stamps `subject.id` so the post-pipeline
// payload reflects who ran last — useful for verifying that the
// chain produced the expected accumulated state.

struct RecordingResolver {
    cfg: PluginConfig,
    name: String,
    ledger: Arc<Mutex<Vec<String>>>,
    /// Number of times this instance has been invoked. Used to verify
    /// that per-step config overrides actually produce a fresh instance
    /// rather than reusing the base.
    invocation_count: Arc<AtomicUsize>,
    /// Optional sink for what `Extensions` slots the plugin saw on
    /// invocation. Used by cap-gating tests. `None` when the test
    /// doesn't care about visibility.
    extensions_observation: Arc<Mutex<Option<IdentityExtensionsObservation>>>,
}

/// What an identity resolver saw in `Extensions` during invocation —
/// drives the cap-gating tests. Only includes slots the tests check
/// (security.subject id, labels).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IdentityExtensionsObservation {
    saw_subject_id: Option<String>,
    saw_labels: Vec<String>,
}

#[async_trait]
impl Plugin for RecordingResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for RecordingResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        self.ledger.lock().unwrap().push(self.name.clone());
        self.invocation_count.fetch_add(1, Ordering::SeqCst);

        // Capability-gating observation. cpex-core's executor calls
        // `filter_extensions(&ext, &caps)` BEFORE handing us `ext`,
        // so this snapshot reflects exactly what our declared
        // capabilities expose.
        *self.extensions_observation.lock().unwrap() =
            Some(IdentityExtensionsObservation {
                saw_subject_id: ext
                    .security
                    .as_ref()
                    .and_then(|s| s.subject.as_ref())
                    .and_then(|s| s.id.clone()),
                saw_labels: ext
                    .security
                    .as_ref()
                    .map(|s| s.labels.iter().cloned().collect())
                    .unwrap_or_default(),
            });

        let mut updated = payload.clone();
        updated.subject = Some(SubjectExtension {
            id: Some(self.name.clone()),
            ..Default::default()
        });
        PluginResult::modify_payload(updated)
    }
}

// =====================================================================
// Test factory — used to build plugin instances from a config block
// so route-level `config:` overrides can produce fresh instances via
// `create_override_instance`.
// =====================================================================

struct RecordingFactory {
    ledger: Arc<Mutex<Vec<String>>>,
    /// Count of *factory invocations* (i.e. instance constructions).
    /// Distinct from `invocation_count` on individual plugins —
    /// asserts that a config override produced a NEW instance.
    factory_calls: Arc<AtomicUsize>,
    /// Optional shared observation sink — when set, every plugin
    /// the factory builds writes its extensions-view snapshot here
    /// on invocation. The test holds the same Arc and reads it
    /// after dispatch. `None` means observations are off (existing
    /// tests don't need them and shouldn't pay the wiring cost).
    observation_sink: Option<Arc<Mutex<Option<IdentityExtensionsObservation>>>>,
}

impl PluginFactory for RecordingFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<PluginInstance, Box<cpex_core::error::PluginError>> {
        self.factory_calls.fetch_add(1, Ordering::SeqCst);
        let plugin = Arc::new(RecordingResolver {
            cfg: config.clone(),
            name: config.name.clone(),
            ledger: Arc::clone(&self.ledger),
            invocation_count: Arc::new(AtomicUsize::new(0)),
            extensions_observation: self
                .observation_sink
                .clone()
                .unwrap_or_else(|| Arc::new(Mutex::new(None))),
        });
        let adapter: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin: plugin as Arc<dyn Plugin>,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, adapter)],
        })
    }
}

// =====================================================================
// Test helpers
// =====================================================================

/// Build the request Extensions with MetaExtension set so route
/// filtering kicks in. Without `meta`, the filter falls through to
/// chain dispatch (all entries returned) — that's the wrong code
/// path to be testing.
fn ext_for_tool(tool_name: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_string()),
            entity_name: Some(tool_name.to_string()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn build_payload(token: &str) -> IdentityPayload {
    IdentityPayload::new(token, TokenSource::Bearer)
}

/// Standard set-up: PluginManager with the recording factory
/// registered, plus a shared ledger and factory-call counter the
/// test asserts on. Doesn't wire extensions observation —
/// existing tests don't need it.
fn manager_with_recording_factory() -> (
    Arc<PluginManager>,
    Arc<Mutex<Vec<String>>>,
    Arc<AtomicUsize>,
) {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "recording",
        Box::new(RecordingFactory {
            ledger: Arc::clone(&ledger),
            factory_calls: Arc::clone(&factory_calls),
            observation_sink: None,
        }),
    );
    (mgr, ledger, factory_calls)
}

/// Cap-gating-flavored set-up: also returns a shared `observation_sink`
/// the test holds onto so it can inspect what extensions the plugin
/// actually saw after invocation. Every plugin the factory builds
/// writes its observation to this shared Arc (latest wins).
fn manager_with_observing_factory() -> (
    Arc<PluginManager>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Option<IdentityExtensionsObservation>>>,
) {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let observation_sink: Arc<Mutex<Option<IdentityExtensionsObservation>>> =
        Arc::new(Mutex::new(None));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "recording",
        Box::new(RecordingFactory {
            ledger: Arc::clone(&ledger),
            factory_calls: Arc::clone(&factory_calls),
            observation_sink: Some(Arc::clone(&observation_sink)),
        }),
    );
    (mgr, ledger, observation_sink)
}

// =====================================================================
// Scenarios
// =====================================================================

/// Baseline: route's `identity:` block dispatches the listed plugins,
/// in declared order, for `identity.resolve`. The ledger should
/// reflect the YAML order verbatim — proves the per-route binding +
/// preserved order story end-to-end.
#[tokio::test]
async fn route_identity_block_dispatches_in_declared_order() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    // Three identity plugins, all registered under `identity.resolve`.
    // Route declares them in REVERSE priority order to prove that
    // routing follows the `identity:` declaration, not chain priority.
    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: jwt-a
    kind: recording
    hooks: [identity.resolve]
    priority: 10
  - name: jwt-b
    kind: recording
    hooks: [identity.resolve]
    priority: 20
  - name: jwt-c
    kind: recording
    hooks: [identity.resolve]
    priority: 30

routes:
  - tool: get_weather
    identity:
      - jwt-c       # priority 30 — would naturally run LAST in chain order
      - jwt-a       # priority 10 — would naturally run FIRST
      - jwt-b       # priority 20
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "pipeline should allow; violation = {:?}",
        result.violation,
    );

    // Order matches the YAML's `identity:` declaration, NOT plugin priority.
    let firings = ledger.lock().unwrap().clone();
    assert_eq!(firings, vec!["jwt-c", "jwt-a", "jwt-b"]);
}

/// `identity:` is hook-specific. Plugins in the route's `plugins:`
/// block (which means "per-route overrides" in APL-driven routes
/// and "per-route binding" otherwise) must NOT fire for the
/// identity.resolve hook. This is the load-bearing test for
/// Option 1 — the design decision that `identity:` is its own
/// dispatch list, independent of `plugins:`.
#[tokio::test]
async fn route_plugins_block_does_not_bind_identity_resolve() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    // The route declares `identity:` with corp-jwt, and `plugins:`
    // with rogue-jwt. rogue-jwt also registers under identity.resolve
    // — but should NOT fire for the identity.resolve hook on this
    // route because it's listed in `plugins:`, not `identity:`.
    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: rogue-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    identity:
      - corp-jwt
    plugins:
      - rogue-jwt
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // Only corp-jwt fired — rogue-jwt was in `plugins:`, not
    // `identity:`, so it's NOT bound for this hook on this route.
    assert_eq!(ledger.lock().unwrap().clone(), vec!["corp-jwt"]);
}

/// A route with no `identity:` block produces zero identity
/// dispatches even when the entity_type / entity_name match. The
/// plugins ARE registered under identity.resolve, but no route
/// binds them, so the route-filter returns an empty entry list.
#[tokio::test]
async fn route_without_identity_block_dispatches_no_resolvers() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    # No identity: block.
    plugins:
      - corp-jwt
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // No identity plugins fired — `identity:` was absent, so the
    // route binds nothing for the identity.resolve hook even though
    // corp-jwt is in `plugins:`.
    assert!(ledger.lock().unwrap().is_empty());
}

/// A route declared for a different tool doesn't bind identity for
/// this request — proves scope/entity matching still works under
/// the new resolver path.
#[tokio::test]
async fn identity_route_filter_respects_entity_match() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_compensation
    identity:
      - corp-jwt
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    // Request for a DIFFERENT tool — corp-jwt should not fire.
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("unrelated_tool"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert!(
        ledger.lock().unwrap().is_empty(),
        "identity must NOT fire for a non-matching route",
    );
}

/// Per-step `config_override` produces a fresh plugin instance via
/// the existing `create_override_instance` pathway. The factory
/// call count goes up by one each time the route's identity step
/// is dispatched with an override — proves the wrapper around
/// `resolve_identity_plugins_for_route` correctly threads the
/// override through to `filter_entries_by_route`'s override branch.
#[tokio::test]
async fn per_step_config_override_produces_fresh_instance() {
    let (mgr, _ledger, factory_calls) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
    config:
      audience: default-aud

routes:
  - tool: get_weather
    identity:
      - name: corp-jwt
        config:
          audience: route-specific-aud
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    // Sanity: factory was called once for the base plugin during
    // load_config. Track from here.
    let base_calls = factory_calls.load(Ordering::SeqCst);

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // One additional factory call for the override instance.
    assert_eq!(
        factory_calls.load(Ordering::SeqCst),
        base_calls + 1,
        "config_override should produce a new factory call",
    );
}

/// Slice C — end-to-end inheritance: global.identity contributes to
/// the dispatch lineup for routes that declare no identity block of
/// their own. Verifies the dispatch path picks up the global layer.
#[tokio::test]
async fn global_identity_inherited_when_route_has_no_block() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

global:
  identity:
    - corp-jwt

routes:
  - tool: get_weather
"#;
    let parsed = cpex_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert_eq!(
        ledger.lock().unwrap().clone(),
        vec!["corp-jwt"],
        "global identity should fire when the route declares none",
    );
}

/// Full stack — global + tag bundle + route — in declared order.
/// Proves the merge actually flows the layers through cpex-core's
/// dispatch in the order the resolver guarantees.
#[tokio::test]
async fn global_tag_route_identity_stack_dispatches_in_order() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: workday-saml
    kind: recording
    hooks: [identity.resolve]
  - name: agent-context
    kind: recording
    hooks: [identity.resolve]

global:
  identity:
    - corp-jwt
  policies:
    finance:
      identity:
        - workday-saml

routes:
  - tool: get_compensation
    meta:
      tags: [finance]
    identity:
      - agent-context
"#;
    let parsed = cpex_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_compensation"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // Order: global → tag bundle → route. The ledger captures the
    // actual dispatch order (preserves the resolver's stacking).
    assert_eq!(
        ledger.lock().unwrap().clone(),
        vec!["corp-jwt", "workday-saml", "agent-context"],
    );
}

/// Route opts out via `replace_inherited: true` — inherited layers
/// (global, tag bundles) are dropped. Only the route's steps run.
#[tokio::test]
async fn replace_inherited_drops_inherited_layers_end_to_end() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: workday-saml
    kind: recording
    hooks: [identity.resolve]
  - name: legacy-basic-auth
    kind: recording
    hooks: [identity.resolve]

global:
  identity:
    - corp-jwt
  policies:
    finance:
      identity:
        - workday-saml

routes:
  - tool: legacy_endpoint
    meta:
      tags: [finance]
    identity:
      replace_inherited: true
      steps:
        - legacy-basic-auth
"#;
    let parsed = cpex_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("legacy_endpoint"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // Only the route's step ran — global and tag-bundle layers
    // were dropped because `replace_inherited: true`.
    assert_eq!(
        ledger.lock().unwrap().clone(),
        vec!["legacy-basic-auth"],
    );
}

/// `replace_inherited: true` + `steps: []` — the explicit
/// "anonymous route, no identity" knob. Zero plugins fire even
/// though global identity is configured.
#[tokio::test]
async fn replace_inherited_with_empty_steps_yields_anonymous_route() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

global:
  identity:
    - corp-jwt

routes:
  - tool: public_endpoint
    identity:
      replace_inherited: true
      steps: []
"#;
    let parsed = cpex_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("public_endpoint"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    assert!(
        ledger.lock().unwrap().is_empty(),
        "anonymous-route opt-out should suppress global identity",
    );
}

/// Sanity that an empty Vec from the resolver (route has identity
/// but with `replace_inherited: true` and zero steps — the explicit
/// "opt out" knob) results in zero dispatches.
#[tokio::test]
async fn route_with_empty_identity_steps_dispatches_nothing() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    identity:
      replace_inherited: true
      steps: []
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert!(ledger.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------
// Capability gating on the identity dispatch path.
//
// Identity plugins go through cpex-core's executor like every other
// hook family — meaning `filter_extensions(&ext, &caps)` runs before
// each handler invoke and narrows what the plugin sees to its
// declared capabilities. These tests pin that behavior for the
// route-level identity dispatch path (Slice A).
//
// Identity is unusual in that resolvers typically WRITE state (subject,
// chain) rather than read it — but they still need read capabilities
// for any extension-derived context they consult during resolution
// (e.g., a `read_meta`-gated resolver that branches on entity tags).
// ---------------------------------------------------------------------

/// Build extensions seeded with subject + label so cap-gating tests
/// can verify what a resolver sees post-filter.
fn ext_for_tool_with_subject_and_label(
    tool_name: &str,
    subject_id: &str,
    label: &str,
) -> Extensions {
    use cpex_core::extensions::{SecurityExtension, SubjectExtension};
    let mut sec = SecurityExtension::default();
    sec.subject = Some(SubjectExtension {
        id: Some(subject_id.to_string()),
        ..Default::default()
    });
    sec.add_label(label);
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_string()),
            entity_name: Some(tool_name.to_string()),
            ..Default::default()
        })),
        security: Some(Arc::new(sec)),
        ..Default::default()
    }
}

/// Identity resolver declaring `read_subject` sees `subject.id` in
/// Extensions but NOT `security.labels` — the executor strips the
/// labels slot because the plugin doesn't hold `read_labels`.
#[tokio::test]
async fn identity_plugin_with_read_subject_sees_subject_but_not_labels() {
    let (mgr, _ledger, sink) = manager_with_observing_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: scoped-jwt
    kind: recording
    hooks: [identity.resolve]
    capabilities: [read_subject]

routes:
  - tool: get_weather
    identity:
      - scoped-jwt
"#;
    let parsed = cpex_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    // Extensions populated with BOTH subject (id=alice) AND a label
    // (pii). The plugin should see subject only.
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool_with_subject_and_label("get_weather", "alice", "pii"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let obs = sink
        .lock()
        .unwrap()
        .clone()
        .expect("plugin should have recorded its view");

    assert_eq!(
        obs.saw_subject_id.as_deref(),
        Some("alice"),
        "read_subject cap should expose subject.id",
    );
    assert!(
        obs.saw_labels.is_empty(),
        "without read_labels, labels must be hidden — saw: {:?}",
        obs.saw_labels,
    );
}

/// Identity resolver with NO capabilities sees a fully-stripped
/// Extensions view. Negative case: confirms the executor's per-entry
/// filter actually hides slots when no cap is declared.
#[tokio::test]
async fn identity_plugin_without_caps_sees_stripped_extensions() {
    let (mgr, _ledger, sink) = manager_with_observing_factory();

    let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: capless-jwt
    kind: recording
    hooks: [identity.resolve]
    # capabilities: []  (omitted entirely; same effect)

routes:
  - tool: get_weather
    identity:
      - capless-jwt
"#;
    let parsed = cpex_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool_with_subject_and_label("get_weather", "alice", "pii"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let obs = sink
        .lock()
        .unwrap()
        .clone()
        .expect("plugin should have recorded its view");

    assert!(
        obs.saw_subject_id.is_none(),
        "without read_subject, subject must be hidden — saw: {:?}",
        obs.saw_subject_id,
    );
    assert!(
        obs.saw_labels.is_empty(),
        "without read_labels, labels must be hidden",
    );
}
