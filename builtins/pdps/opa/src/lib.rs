// Location: ./builtins/pdps/opa/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// cpex-pdp-opa — `PdpResolver` over the pure-Rust `regorus` Rego interpreter.
//
// (Full crate docs land with the resolver in U3/U4.)

pub mod input;

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
