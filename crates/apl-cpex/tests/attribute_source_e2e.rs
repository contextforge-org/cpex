// Location: ./crates/apl-cpex/tests/attribute_source_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end: a static `data.*` attribute tree, set on the visitor before
// the config walk, flows into every request's bag so policy predicates can
// read it. Covers R3 of docs/apl-restrict-effect-design.md — the load →
// bag path (static dot-path references; R3b interpolation is separate).

use std::sync::Arc;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::{
    CandidateConstraintExtension, Extensions, MetaExtension, SecurityExtension, SubjectExtension,
};
use cpex_core::manager::PluginManager;

use apl_cpex::{merge_attribute_docs, register_apl, AplOptions, DispatchCache, MemorySessionStore};

fn cmf_payload(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_string());
    meta.entity_name = Some(name.to_string());
    meta
}

/// Build a manager, set the given `data.*` tree, load `yaml`, initialize.
async fn build_manager_with_data(yaml: &str, data_docs_yaml: &str) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    let visitor = register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );

    // Load the tree from an in-memory "file" and install it BEFORE the
    // config walk (handlers capture the tree during load_config_yaml).
    let doc: serde_json::Value = serde_yaml::from_str(data_docs_yaml).unwrap();
    let tree = merge_attribute_docs([("attrs.yaml".to_string(), doc)]).unwrap();
    visitor.set_attribute_tree(tree);

    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

async fn invoke_tool(mgr: &Arc<PluginManager>, tool: &str) -> bool {
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool(tool))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    result.continue_processing
}

const ROUTE: &str = r#"
routes:
  - tool: fetch
    apl:
      pre_invocation:
        - "data.org.default_region == 'eu': deny('eu-restricted')"
"#;

/// The predicate reads `data.org.default_region`; with the tree saying
/// `eu`, the deny fires.
#[tokio::test]
async fn policy_reads_data_namespace_and_denies() {
    let data = "data:\n  org:\n    default_region: eu\n";
    let mgr = build_manager_with_data(ROUTE, data).await;
    assert!(
        !invoke_tool(&mgr, "fetch").await,
        "data.org.default_region == 'eu' should deny"
    );
}

/// Same route, different tree value — the predicate is false, request
/// continues. Proves the value actually comes from the tree.
#[tokio::test]
async fn policy_reads_data_namespace_and_allows() {
    let data = "data:\n  org:\n    default_region: us\n";
    let mgr = build_manager_with_data(ROUTE, data).await;
    assert!(
        invoke_tool(&mgr, "fetch").await,
        "data.org.default_region == 'us' should not trip the eu deny"
    );
}

/// No tree set at all → `data.*` keys are simply absent; an equality
/// predicate against a missing key is false, so the request continues.
#[tokio::test]
async fn missing_data_key_is_absent_not_error() {
    // Build without any data tree (empty docs).
    let mgr = build_manager_with_data(ROUTE, "data: {}\n").await;
    assert!(
        invoke_tool(&mgr, "fetch").await,
        "absent data.* key must not trip the deny"
    );
}

// ----- R3b: interpolation end-to-end -----

/// Invoke with a subject id so `subject.id` lands in the bag.
async fn invoke_as_subject(mgr: &Arc<PluginManager>, tool: &str, subject_id: &str) -> bool {
    let mut subject = SubjectExtension::default();
    subject.id = Some(subject_id.to_string());
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool(tool))),
        security: Some(Arc::new(SecurityExtension {
            subject: Some(subject),
            ..Default::default()
        })),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    result.continue_processing
}

const INTERP_ROUTE: &str = r#"
routes:
  - tool: infer
    apl:
      pre_invocation:
        - "data.agents[subject.id].region == 'eu': deny('agent pinned to eu')"
"#;

const AGENTS_DATA: &str = r#"
data:
  agents:
    eu-bot: { region: eu }
    us-bot: { region: us }
"#;

/// The request's `subject.id` indexes the data tree at eval time:
/// `eu-bot` resolves to `data.agents.eu-bot.region == eu` → deny.
#[tokio::test]
async fn interpolation_resolves_subject_id_end_to_end() {
    let mgr = build_manager_with_data(INTERP_ROUTE, AGENTS_DATA).await;
    assert!(
        !invoke_as_subject(&mgr, "infer", "eu-bot").await,
        "eu-bot resolves to region=eu → deny"
    );
}

/// Same route + tree, different caller → different resolved path → allow.
#[tokio::test]
async fn interpolation_different_subject_allows() {
    let mgr = build_manager_with_data(INTERP_ROUTE, AGENTS_DATA).await;
    assert!(
        invoke_as_subject(&mgr, "infer", "us-bot").await,
        "us-bot resolves to region=us → the eu deny does not fire"
    );
}

// ----- data.* referenced as a restrict field value -----

/// Invoke as a subject and return the emitted candidate constraint, if any.
async fn constraint_as_subject(
    mgr: &Arc<PluginManager>,
    tool: &str,
    subject_id: &str,
) -> Option<CandidateConstraintExtension> {
    let mut subject = SubjectExtension::default();
    subject.id = Some(subject_id.to_string());
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool(tool))),
        security: Some(Arc::new(SecurityExtension {
            subject: Some(subject),
            ..Default::default()
        })),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    result
        .modified_extensions
        .and_then(|e| e.candidate_constraint.as_ref().map(|a| (**a).clone()))
}

const REF_ROUTE: &str = r#"
routes:
  - tool: infer
    apl:
      pre_invocation:
        - restrict:
            allow_models: "data.agents[subject.id].allowed_models"
"#;

const REF_DATA: &str = r#"
data:
  agents:
    support-bot: { allowed_models: ["vllm/*"] }
    research-bot: { allowed_models: ["anthropic/*", "vllm/*"] }
"#;

/// One `restrict` rule, per-caller value: the `data.*` reference resolves
/// each agent's own allow-list from the static tree at request time.
#[tokio::test]
async fn restrict_field_reference_resolves_per_caller() {
    let mgr = build_manager_with_data(REF_ROUTE, REF_DATA).await;

    let support = constraint_as_subject(&mgr, "infer", "support-bot")
        .await
        .expect("support-bot constraint");
    assert_eq!(support.allow_models, Some(vec!["vllm/*".to_string()]));

    let research = constraint_as_subject(&mgr, "infer", "research-bot")
        .await
        .expect("research-bot constraint");
    assert_eq!(
        research.allow_models,
        Some(vec!["anthropic/*".to_string(), "vllm/*".to_string()])
    );
}

/// An agent absent from the tree resolves to an empty allow-list — a real
/// (impossible) constraint that fails closed via `on_empty`, never an
/// unconstrained pass.
#[tokio::test]
async fn restrict_field_reference_absent_agent_is_empty() {
    let mgr = build_manager_with_data(REF_ROUTE, REF_DATA).await;
    let c = constraint_as_subject(&mgr, "infer", "unknown-bot")
        .await
        .expect("constraint still emitted");
    assert_eq!(c.allow_models, Some(vec![]));
}

// ----- Declarative `global.apl.attribute_files` -----

fn default_opts() -> AplOptions {
    AplOptions {
        dispatch_cache: Arc::new(DispatchCache::new()),
        session_store: Arc::new(MemorySessionStore::new()),
        pdps: Vec::new(),
        pdp_factories: Vec::new(),
        session_store_factories: Vec::new(),
        base_capabilities: None,
    }
}

/// Write attribute files to a fresh temp dir; returns the dir + the paths.
fn write_attr_files(tag: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let dir = std::env::temp_dir().join(format!("apl_decl_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = files
        .iter()
        .map(|(name, body)| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        })
        .collect();
    (dir, paths)
}

/// `global.apl.attribute_files` loads the tree during the config walk —
/// no `set_attribute_tree` call — and it flows into the bag.
#[tokio::test]
async fn declarative_attribute_files_load_into_bag() {
    let (dir, paths) = write_attr_files("load", &[("org.yaml", "data:\n  org:\n    default_region: eu\n")]);

    let yaml = format!(
        r#"
global:
  apl:
    attribute_files:
      - {path}
routes:
  - tool: fetch
    apl:
      pre_invocation:
        - "data.org.default_region == 'eu': deny('eu-restricted')"
"#,
        path = paths[0].display()
    );

    let mgr = Arc::new(PluginManager::default());
    register_apl(&mgr, default_opts());
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    assert!(
        !invoke_tool(&mgr, "fetch").await,
        "declaratively-loaded data.org.default_region == 'eu' should deny"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Multiple files merge (disjoint subtrees combine).
#[tokio::test]
async fn declarative_multiple_files_merge() {
    let (dir, paths) = write_attr_files(
        "merge",
        &[
            ("org.yaml", "data:\n  org:\n    default_region: us\n"),
            ("agents.yaml", "data:\n  agents:\n    eu-bot:\n      region: eu\n"),
        ],
    );

    let yaml = format!(
        r#"
global:
  apl:
    attribute_files:
      - {a}
      - {b}
routes:
  - tool: infer
    apl:
      pre_invocation:
        - "data.agents[subject.id].region == 'eu': deny('pinned')"
"#,
        a = paths[0].display(),
        b = paths[1].display()
    );

    let mgr = Arc::new(PluginManager::default());
    register_apl(&mgr, default_opts());
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    assert!(!invoke_as_subject(&mgr, "infer", "eu-bot").await, "eu-bot → deny");
    std::fs::remove_dir_all(&dir).ok();
}

/// An injected tree (set_attribute_tree) beats declarative attribute_files.
#[tokio::test]
async fn injected_tree_beats_declarative_files() {
    let (dir, paths) = write_attr_files("prec", &[("org.yaml", "data:\n  org:\n    default_region: eu\n")]);

    let yaml = format!(
        r#"
global:
  apl:
    attribute_files:
      - {path}
routes:
  - tool: fetch
    apl:
      pre_invocation:
        - "data.org.default_region == 'eu': deny('eu-restricted')"
"#,
        path = paths[0].display()
    );

    let mgr = Arc::new(PluginManager::default());
    let visitor = register_apl(&mgr, default_opts());
    // Inject a tree saying `us` — must win over the file's `eu`.
    let doc: serde_json::Value =
        serde_yaml::from_str("data:\n  org:\n    default_region: us\n").unwrap();
    visitor.set_attribute_tree(merge_attribute_docs([("inj".to_string(), doc)]).unwrap());
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    assert!(
        invoke_tool(&mgr, "fetch").await,
        "injected tree (region=us) must win over attribute_files (region=eu)"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A missing attribute file fails config load (fail-fast).
#[tokio::test]
async fn missing_attribute_file_fails_config_load() {
    let yaml = r#"
global:
  apl:
    attribute_files:
      - /no/such/attrs.yaml
routes:
  - tool: fetch
    apl:
      pre_invocation:
        - "require(authenticated)"
"#;
    let mgr = Arc::new(PluginManager::default());
    register_apl(&mgr, default_opts());
    assert!(
        mgr.load_config_yaml(yaml).is_err(),
        "a missing attribute file must fail config load"
    );
}
