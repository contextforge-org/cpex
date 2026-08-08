// Location: ./builtins/pdps/opa/src/input.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Bag → Rego `input` mapping.
//
// APL's `AttributeBag` is a flat `HashMap<String, AttributeValue>` with dotted
// keys (`subject.id`, `role.hr`, `delegation.depth`). Rego wants a nested
// document so `input.subject.id` reads as field selection. This module rebuilds
// the flat bag into a nested JSON object that becomes the engine's `input`.
//
// This mirrors the tree-building and type coercions in `cpex-pdp-cel`'s
// `activation.rs` so a policy author's mental model of the attribute
// vocabulary is identical across the two backends. It is ported rather than
// shared so this crate stays apl-core-only at compile time.
//
// Type mapping (`AttributeValue` → JSON):
//   Bool      → bool
//   Int       → integer
//   Float     → integer when it is a whole number in i64 range, else float
//   String    → string
//   StringSet → array of strings, sorted (so `input.x[0]` is deterministic)
//
// Collision rule: if a key is both a leaf and a namespace prefix (`delegation`
// AND `delegation.depth`), the namespace (object) wins and the scalar leaf is
// dropped with a `tracing::warn!`, matching the CEL resolver.

use std::collections::BTreeMap;

use apl_core::attributes::{AttributeBag, AttributeValue};
use serde_json::{Map, Number, Value};

/// Build the Rego `input` document from the policy bag.
///
/// Every dotted bag key becomes a nested field: `subject.id` → `{"subject":
/// {"id": ...}}`. Single-segment keys (`authenticated`) become top-level
/// fields. The result is always a JSON object (an empty bag yields `{}`).
pub fn bag_to_input(bag: &AttributeBag) -> Value {
    let mut root: BTreeMap<String, Node> = BTreeMap::new();
    for (key, value) in bag.iter() {
        let segments: Vec<&str> = key.split('.').collect();
        insert(&mut root, key, &segments, attr_to_value(value));
    }
    node_map_to_value(root)
}

/// Internal tree node: either a leaf scalar/array or a nested namespace.
enum Node {
    Leaf(Value),
    Branch(BTreeMap<String, Node>),
}

/// Insert a leaf at the dotted path, creating intermediate branches.
/// Namespace-wins on leaf/branch collisions (see module docs).
fn insert(level: &mut BTreeMap<String, Node>, full_key: &str, segments: &[&str], leaf: Value) {
    // `bag.iter()` never yields empty keys today, but return cleanly rather
    // than panic if a future bag implementation emits one.
    let Some((head, rest)) = segments.split_first() else {
        return;
    };
    let head = (*head).to_string();

    if rest.is_empty() {
        match level.get(&head) {
            Some(Node::Branch(_)) => {
                tracing::warn!(
                    key = %full_key,
                    "OPA input: scalar key collides with an existing namespace; \
                     keeping the namespace and dropping the scalar"
                );
            },
            _ => {
                level.insert(head, Node::Leaf(leaf));
            },
        }
        return;
    }

    let entry = level
        .entry(head)
        .or_insert_with(|| Node::Branch(BTreeMap::new()));
    if let Node::Leaf(_) = entry {
        tracing::warn!(
            key = %full_key,
            "OPA input: namespace prefix collides with an existing scalar; \
             promoting to a namespace and dropping the scalar"
        );
        *entry = Node::Branch(BTreeMap::new());
    }
    if let Node::Branch(child) = entry {
        insert(child, full_key, rest, leaf);
    }
}

/// Recursively convert a tree of nodes into a JSON object value.
fn node_map_to_value(children: BTreeMap<String, Node>) -> Value {
    let mut map = Map::new();
    for (k, child) in children {
        map.insert(k, node_to_value(child));
    }
    Value::Object(map)
}

fn node_to_value(node: Node) -> Value {
    match node {
        Node::Leaf(v) => v,
        Node::Branch(children) => node_map_to_value(children),
    }
}

/// Convert one `AttributeValue` to a JSON value.
fn attr_to_value(attr: &AttributeValue) -> Value {
    match attr {
        AttributeValue::Bool(b) => Value::Bool(*b),
        AttributeValue::Int(i) => Value::Number((*i).into()),
        AttributeValue::Float(f) => float_to_value(*f),
        AttributeValue::String(s) => Value::String(s.clone()),
        // StringSet → sorted array. Rego treats the value as a JSON array;
        // sorting makes any index-dependent policy deterministic across runs.
        AttributeValue::StringSet(set) => {
            let mut sorted: Vec<&String> = set.iter().collect();
            sorted.sort();
            Value::Array(
                sorted
                    .into_iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            )
        },
    }
}

/// Yield an `f64` as a JSON integer when it is a whole number in `i64` range,
/// otherwise a JSON float. Keeps parity with CEL's `float_to_value` so a bag
/// value populated as `Float(2.0)` reads as `2` for an author. A non-finite
/// float has no JSON representation and becomes `null`.
fn float_to_value(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
        Value::Number((f as i64).into())
    } else {
        Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use regorus::Engine;

    /// Evaluate a boolean Rego expression against an input built from `bag`.
    /// Wraps the expression in a rule so we exercise the exact input path the
    /// resolver uses (`set_input_json` + `eval_rule`).
    fn rego_eval(expr: &str, bag: &AttributeBag) -> bool {
        let input = bag_to_input(bag);
        let mut engine = Engine::new();
        engine
            .add_policy(
                "t.rego".to_string(),
                format!("package t\nresult if {{ {expr} }}\n"),
            )
            .unwrap();
        engine.set_input_json(&input.to_string()).unwrap();
        engine
            .eval_rule("data.t.result".to_string())
            .unwrap()
            .as_bool()
            .copied()
            .unwrap_or(false)
    }

    #[test]
    fn dotted_keys_become_nested_fields() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        bag.set("subject.type", "user");
        assert!(rego_eval("input.subject.id == \"alice\"", &bag));
        assert!(rego_eval("input.subject.type == \"user\"", &bag));
    }

    #[test]
    fn single_segment_key_is_top_level_field() {
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        assert!(rego_eval("input.authenticated == true", &bag));
    }

    #[test]
    fn bool_int_float_string_scalars() {
        let mut bag = AttributeBag::new();
        bag.set("role.hr", true);
        bag.set("delegation.depth", 2_i64);
        bag.set("intent.confidence", 0.92_f64);
        bag.set("subject.id", "alice");
        assert!(rego_eval("input.role.hr == true", &bag));
        assert!(rego_eval("input.delegation.depth == 2", &bag));
        assert!(rego_eval("input.intent.confidence > 0.9", &bag));
        assert!(rego_eval("input.subject.id == \"alice\"", &bag));
    }

    #[test]
    fn whole_number_float_reads_as_integer() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2.0_f64);
        // Emitted as the JSON integer 2 (not 2.0), so an author comparing to an
        // integer literal gets the natural result.
        assert_eq!(
            bag_to_input(&bag)["delegation"]["depth"],
            serde_json::json!(2)
        );
        assert!(rego_eval("input.delegation.depth == 2", &bag));
    }

    #[test]
    fn string_set_becomes_sorted_array() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["zeta".to_string(), "alpha".to_string(), "mu".to_string()]),
        );
        assert!(rego_eval("\"alpha\" in input.session.labels", &bag));
        assert!(rego_eval("input.session.labels[0] == \"alpha\"", &bag));
        assert!(rego_eval("input.session.labels[2] == \"zeta\"", &bag));
    }

    #[test]
    fn namespace_wins_on_leaf_collision() {
        let mut bag = AttributeBag::new();
        bag.set("delegation", "scalar-value");
        bag.set("delegation.depth", 3_i64);
        // The namespace must win so `delegation.depth` resolves rather than the
        // scalar shadowing it.
        assert!(rego_eval("input.delegation.depth == 3", &bag));
    }

    #[test]
    fn empty_bag_is_empty_object() {
        let bag = AttributeBag::new();
        assert_eq!(bag_to_input(&bag), serde_json::json!({}));
    }
}
