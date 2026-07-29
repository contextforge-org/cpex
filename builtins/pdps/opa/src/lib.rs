// Location: ./builtins/pdps/opa/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// cpex-pdp-opa — `PdpResolver` over Microsoft's pure-Rust `regorus` Rego
// interpreter.
//
// # Where this lives in the stack
//
//   APL evaluator (apl-core)
//        │  `opa: { query: "data.authz.allow" }` step
//        ▼
//   PdpRouter (apl-cpex)        — dispatches by dialect (PdpDialect::Opa)
//        │  resolver.evaluate(call, bag)
//        ▼
//   OpaResolver                 — THIS CRATE
//        │  bag → Rego input, clone base engine, eval query
//        ▼
//   regorus::Engine             — embedded Rego evaluation, no sidecar
//
// # Policy source (hybrid)
//
// Rego modules and `data` are declared in the `global.pdp` block and parsed
// once at factory-build time; a route step may also carry an inline `module`.
// See `resolver::OpaResolver::from_config` for the config shape and
// `factory::OpaPdpFactory` for how the visitor builds it.
//
// # The attribute vocabulary (bag → input)
//
// APL's flat, dotted `AttributeBag` (`subject.id`, `delegation.depth`,
// `session.labels`) is rebuilt into a nested Rego `input` document so authors
// write `input.subject.id`. See `input::bag_to_input` — the mapping mirrors
// the CEL resolver's so the vocabulary is identical across backends.
//
// # Decision contract
//
// The step's `query` must resolve to a boolean, a decision object (whose
// allow/deny bit is read from `decision_field`, default `allow`), or a
// set/array (the deny-set idiom: empty → allow, non-empty → deny). An
// undefined result is a clean deny — Rego's idiomatic "not granted" — never
// routed through `on_error`. A value carrying no decision, or a genuine eval
// error, is governed by `on_error` (default `deny`). A Rego parse/compile
// error always denies. See `decision::map_query_result`.
//
// # Evaluation model
//
// A base `regorus::Engine` holds the compiled global policy + data. Because
// the `arc` feature makes that state `Arc`-shared, the resolver clones the base
// per request (cheap), sets the request `input`, and evaluates — no lock on the
// hot path. Inline modules get a bounded prepared-engine cache. See
// `resolver` for the details.

pub mod decision;
pub mod error;
pub mod factory;
pub mod input;
pub mod resolver;

pub use error::BuildError;
pub use factory::OpaPdpFactory;
pub use resolver::{OnError, OpaResolver};

#[cfg(test)]
mod regorus_api_smoke {
    // Pins the exact regorus 0.11 API the resolver is built on: incremental
    // module load, JSON input, query eval, and the Value shapes for allow /
    // deny-set / undefined. If a regorus upgrade changes any of these, this
    // fails loudly here rather than deep in the resolver.
    use regorus::Engine;

    #[test]
    fn bool_query_allow_and_deny() {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "authz.rego".to_string(),
                r#"package authz
default allow := false
allow if input.subject.id == "alice"
"#
                .to_string(),
            )
            .unwrap();

        engine
            .set_input_json(r#"{"subject":{"id":"alice"}}"#)
            .unwrap();
        let v = engine.eval_rule("data.authz.allow".to_string()).unwrap();
        assert_eq!(v.as_bool().copied().ok(), Some(true));

        // Non-match with a `default` → false (not undefined).
        engine
            .set_input_json(r#"{"subject":{"id":"eve"}}"#)
            .unwrap();
        let v = engine.eval_rule("data.authz.allow".to_string()).unwrap();
        assert_eq!(v.as_bool().copied().ok(), Some(false));
    }

    #[test]
    fn undefined_when_no_default_and_no_match() {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "authz.rego".to_string(),
                r#"package authz
allow if input.subject.id == "alice"
"#
                .to_string(),
            )
            .unwrap();
        engine
            .set_input_json(r#"{"subject":{"id":"eve"}}"#)
            .unwrap();
        let v = engine.eval_rule("data.authz.allow".to_string()).unwrap();
        // No matching rule and no `default` → undefined, distinct from false.
        assert!(matches!(v, regorus::Value::Undefined), "got {v:?}");
    }

    #[test]
    fn deny_set_idiom_yields_set() {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "authz.rego".to_string(),
                r#"package authz
deny contains msg if {
    input.subject.id != "alice"
    msg := "subject not allowed"
}
"#
                .to_string(),
            )
            .unwrap();

        // Violating input → non-empty set.
        engine
            .set_input_json(r#"{"subject":{"id":"eve"}}"#)
            .unwrap();
        let v = engine.eval_rule("data.authz.deny".to_string()).unwrap();
        match &v {
            regorus::Value::Set(s) => assert_eq!(s.len(), 1),
            other => panic!("expected Set, got {other:?}"),
        }

        // Passing input → empty set.
        engine
            .set_input_json(r#"{"subject":{"id":"alice"}}"#)
            .unwrap();
        let v = engine.eval_rule("data.authz.deny".to_string()).unwrap();
        match &v {
            regorus::Value::Set(s) => assert!(s.is_empty()),
            other => panic!("expected empty Set, got {other:?}"),
        }
    }

    #[test]
    fn data_document_is_readable_by_policy() {
        let mut engine = Engine::new();
        engine
            .add_data_json(r#"{"roles":{"alice":["reader"]}}"#)
            .unwrap();
        engine
            .add_policy(
                "authz.rego".to_string(),
                r#"package authz
default allow := false
allow if "reader" in data.roles[input.subject.id]
"#
                .to_string(),
            )
            .unwrap();
        engine
            .set_input_json(r#"{"subject":{"id":"alice"}}"#)
            .unwrap();
        let v = engine.eval_rule("data.authz.allow".to_string()).unwrap();
        assert_eq!(v.as_bool().copied().ok(), Some(true));
    }

    #[test]
    fn parse_error_surfaces_at_add_policy() {
        let mut engine = Engine::new();
        let err = engine.add_policy("bad.rego".to_string(), "package x\nallow if {".to_string());
        assert!(err.is_err(), "malformed Rego must fail at add_policy");
    }

    #[test]
    fn clone_shares_compiled_policy_and_isolates_input() {
        let mut base = Engine::new();
        base.add_policy(
            "authz.rego".to_string(),
            r#"package authz
default allow := false
allow if input.subject.id == "alice"
"#
            .to_string(),
        )
        .unwrap();

        let mut a = base.clone();
        a.set_input_json(r#"{"subject":{"id":"alice"}}"#).unwrap();
        let mut b = base.clone();
        b.set_input_json(r#"{"subject":{"id":"eve"}}"#).unwrap();

        assert_eq!(
            a.eval_rule("data.authz.allow".to_string())
                .unwrap()
                .as_bool()
                .copied()
                .ok(),
            Some(true)
        );
        assert_eq!(
            b.eval_rule("data.authz.allow".to_string())
                .unwrap()
                .as_bool()
                .copied()
                .ok(),
            Some(false)
        );
    }
}
