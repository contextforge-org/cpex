// Location: ./crates/apl-pdp-cel/src/activation.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Bag → CEL activation mapping.
//
// APL's `AttributeBag` is a flat `HashMap<String, AttributeValue>` with
// dotted keys (`subject.id`, `role.hr`, `delegation.depth`). CEL wants
// nested structures so `subject.id` reads as field selection on a
// `subject` map. This module rebuilds the flat bag into a tree of CEL
// maps and registers each top-level namespace as a CEL variable.
//
// Type mapping (`AttributeValue` → `cel::Value`):
//   Bool      → Value::Bool
//   Int       → Value::Int
//   Float     → Value::Float
//   String    → Value::String
//   StringSet → Value::List(of String)   (so `"x" in session.labels` works)
//
// Collision rule: if a key is both a leaf and a namespace prefix
// (`delegation` AND `delegation.depth`), the namespace (map) wins and the
// scalar leaf is dropped with a `tracing::warn!`. In practice the cmf
// BagBuilder never emits both, but the bag is an open namespace so we
// resolve it deterministically rather than panic.

use std::collections::{BTreeMap, HashMap};

use apl_core::attributes::{AttributeBag, AttributeValue};
use cel::{Context, Value};

/// Build a CEL evaluation context from the policy bag plus the `cel:`
/// step's extra args.
///
/// - Every dotted bag key becomes nested CEL maps; each top-level segment
///   (`subject`, `role`, `delegation`, `session`, `args`, …) is registered
///   as a CEL variable.
/// - Each top-level key of `extra_args` (everything the author put under
///   `cel:` besides `expr`) is registered as an additional variable —
///   e.g. `resource`, `context` — mirroring how `cedar:` surfaces them.
/// - On a name collision between an `extra_args` key and a bag namespace,
///   the **bag wins** (the bag is the authoritative, framework-populated
///   vocabulary; args can't shadow it by accident).
///
/// The returned context also carries CEL's standard function/macro library
/// (via `Context::default`), so `has()`, `size()`, `all()`, `exists()`,
/// `map()`, `filter()`, string methods, etc. are all available.
pub fn bag_to_context(bag: &AttributeBag, extra_args: &serde_yaml::Value) -> Context<'static> {
    let mut ctx = Context::default();

    // 1. Author-supplied extra args first (so the bag overrides on
    //    collision). Skip `expr` — that's the program text, not a variable.
    if let Some(map) = extra_args.as_mapping() {
        for (k, v) in map {
            let Some(name) = k.as_str() else { continue };
            if name == "expr" {
                continue;
            }
            ctx.add_variable_from_value(name.to_string(), yaml_to_value(v));
        }
    }

    // 2. The bag namespaces (authoritative). Build the tree, then register
    //    each top-level node as a variable.
    let root = build_tree(bag);
    for (name, node) in root {
        ctx.add_variable_from_value(name, node_to_value(node));
    }

    ctx
}

/// Internal tree node: either a leaf scalar/list or a nested namespace.
enum Node {
    Leaf(Value),
    Branch(BTreeMap<String, Node>),
}

/// Build the top-level namespace tree from the flat, dotted bag.
fn build_tree(bag: &AttributeBag) -> BTreeMap<String, Node> {
    let mut root: BTreeMap<String, Node> = BTreeMap::new();
    for (key, value) in bag.iter() {
        let segments: Vec<&str> = key.split('.').collect();
        insert(&mut root, key, &segments, attr_to_value(value));
    }
    root
}

/// Insert a leaf at the dotted path, creating intermediate branches.
/// Namespace-wins on leaf/branch collisions (see module docs).
fn insert(level: &mut BTreeMap<String, Node>, full_key: &str, segments: &[&str], leaf: Value) {
    let (head, rest) = segments.split_first().expect("key never splits empty");
    let head = head.to_string();

    if rest.is_empty() {
        // Terminal segment — place the leaf, unless a namespace already
        // claimed this name (namespace wins).
        match level.get(&head) {
            Some(Node::Branch(_)) => {
                tracing::warn!(
                    key = %full_key,
                    "CEL activation: scalar key collides with an existing namespace; \
                     keeping the namespace and dropping the scalar"
                );
            }
            _ => {
                level.insert(head, Node::Leaf(leaf));
            }
        }
        return;
    }

    // Intermediate segment — descend, converting a leaf into a branch if
    // needed (namespace wins).
    let entry = level.entry(head).or_insert_with(|| Node::Branch(BTreeMap::new()));
    if let Node::Leaf(_) = entry {
        tracing::warn!(
            key = %full_key,
            "CEL activation: namespace prefix collides with an existing scalar; \
             promoting to a namespace and dropping the scalar"
        );
        *entry = Node::Branch(BTreeMap::new());
    }
    if let Node::Branch(child) = entry {
        insert(child, full_key, rest, leaf);
    }
}

/// Recursively convert a tree node into a `cel::Value`.
fn node_to_value(node: Node) -> Value {
    match node {
        Node::Leaf(v) => v,
        Node::Branch(children) => {
            let map: HashMap<String, Value> = children
                .into_iter()
                .map(|(k, child)| (k, node_to_value(child)))
                .collect();
            Value::from(map)
        }
    }
}

/// Convert one `AttributeValue` to a `cel::Value`.
fn attr_to_value(attr: &AttributeValue) -> Value {
    match attr {
        AttributeValue::Bool(b) => Value::from(*b),
        AttributeValue::Int(i) => Value::from(*i),
        AttributeValue::Float(f) => Value::from(*f),
        AttributeValue::String(s) => Value::from(s.clone()),
        // StringSet → list(string). Order is irrelevant for `in` /
        // comprehensions; HashSet iteration order is fine.
        AttributeValue::StringSet(set) => {
            let items: Vec<Value> = set.iter().map(|s| Value::from(s.clone())).collect();
            Value::from(items)
        }
    }
}

/// Convert a `serde_yaml::Value` (author-supplied `cel:` args) to a
/// `cel::Value`. Numbers without a fractional part map to `Int`, otherwise
/// `Float`. Non-string mapping keys are skipped (CEL map keys here are
/// always strings for author ergonomics).
fn yaml_to_value(v: &serde_yaml::Value) -> Value {
    match v {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::from(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else {
                Value::from(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        serde_yaml::Value::String(s) => Value::from(s.clone()),
        serde_yaml::Value::Sequence(seq) => {
            let items: Vec<Value> = seq.iter().map(yaml_to_value).collect();
            Value::from(items)
        }
        serde_yaml::Value::Mapping(map) => {
            let mut out: HashMap<String, Value> = HashMap::new();
            for (k, val) in map {
                if let Some(name) = k.as_str() {
                    out.insert(name.to_string(), yaml_to_value(val));
                }
            }
            Value::from(out)
        }
        // serde_yaml's tagged values are not used in APL configs; treat as null.
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn run_cel(expr: &str, ctx: &Context<'static>) -> Result<Value, String> {
        let program = cel::Program::compile(expr).map_err(|e| e.to_string())?;
        program.execute(ctx).map_err(|e| e.to_string())
    }

    fn truthy(expr: &str, bag: &AttributeBag) -> bool {
        let ctx = bag_to_context(bag, &serde_yaml::Value::Null);
        matches!(run_cel(expr, &ctx), Ok(Value::Bool(true)))
    }

    #[test]
    fn dotted_keys_become_nested_maps() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        bag.set("subject.type", "user");
        assert!(truthy("subject.id == 'alice'", &bag));
        assert!(truthy("subject.type == 'user'", &bag));
    }

    #[test]
    fn bool_int_float_scalars() {
        let mut bag = AttributeBag::new();
        bag.set("role.hr", true);
        bag.set("delegation.depth", 2_i64);
        bag.set("intent.confidence", 0.92_f64);
        assert!(truthy("role.hr", &bag));
        assert!(truthy("delegation.depth <= 2", &bag));
        assert!(truthy("intent.confidence > 0.9", &bag));
    }

    #[test]
    fn single_segment_key_is_top_level_variable() {
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        assert!(truthy("authenticated", &bag));
    }

    #[test]
    fn string_set_becomes_list_for_in_operator() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["PII".to_string(), "compensation".to_string()]),
        );
        assert!(truthy("'PII' in session.labels", &bag));
        assert!(truthy("'compensation' in session.labels", &bag));
        assert!(truthy("!('PHI' in session.labels)", &bag));
        // Comprehension macros work over the list too.
        assert!(truthy("session.labels.exists(l, l == 'PII')", &bag));
    }

    #[test]
    fn has_macro_guards_optional_fields() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        // `subject` exists but has no `email` field → has() is false.
        assert!(truthy("has(subject.id) && !has(subject.email)", &bag));
    }

    #[test]
    fn extra_args_surface_as_variables_bag_wins_on_collision() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        let args = serde_yaml::from_str::<serde_yaml::Value>(
            "resource:\n  kind: document\n  sensitivity: 3\nsubject: shadowed\n",
        )
        .unwrap();
        let ctx = bag_to_context(&bag, &args);
        // Author-supplied `resource` is visible.
        assert!(matches!(
            run_cel("resource.kind == 'document' && resource.sensitivity == 3", &ctx),
            Ok(Value::Bool(true))
        ));
        // `subject` from the bag wins over the args' `subject: shadowed`.
        assert!(matches!(
            run_cel("subject.id == 'alice'", &ctx),
            Ok(Value::Bool(true))
        ));
    }

    #[test]
    fn namespace_wins_on_leaf_collision() {
        // Both `delegation` (scalar) and `delegation.depth` (under a
        // namespace) present — the namespace must win so `delegation.depth`
        // resolves rather than erroring on a scalar field access.
        let mut bag = AttributeBag::new();
        bag.set("delegation", "scalar-value");
        bag.set("delegation.depth", 3_i64);
        assert!(truthy("delegation.depth == 3", &bag));
    }
}
