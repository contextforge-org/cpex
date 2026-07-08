// Location: ./crates/apl-cpex/src/attribute_source.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// FileAttributeSource — the built-in `data.*` provider (design §4.4.1).
//
// Reads a list of attribute files (YAML, each wrapping everything under a
// top-level `data:` mapping) and deep-merges them into one
// `AttributeTree`. Different subtrees combine freely; a genuine same-leaf
// conflict (two files setting the same path to different values) is a
// **load-time error**, not a silent last-wins clobber. Snapshot only in
// v1 (no `watch`); hot-reload is deferred.
//
// `AttributeSource::load` is synchronous (it runs once at startup), so
// this is just plain file I/O plus the merge — no async, no runtime.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use apl_core::attribute_source::{AttributeError, AttributeSource, AttributeTree};

/// Built-in file-backed [`AttributeSource`]. Construct from the paths in
/// `settings.attribute_files`; each is read and deep-merged, in order,
/// into the `data.*` tree.
pub struct FileAttributeSource {
    paths: Vec<PathBuf>,
}

impl FileAttributeSource {
    /// New source over the given files (merged in order).
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
        }
    }

}

impl AttributeSource for FileAttributeSource {
    /// Read and merge the files. Synchronous — runs at startup, off the
    /// request path.
    fn load(&self) -> Result<AttributeTree, AttributeError> {
        let mut docs = Vec::with_capacity(self.paths.len());
        for path in &self.paths {
            let text = std::fs::read_to_string(path)
                .map_err(|e| AttributeError::Load(format!("{}: {}", path.display(), e)))?;
            let doc: Value = serde_yaml::from_str(&text)
                .map_err(|e| AttributeError::Parse(format!("{}: {}", path.display(), e)))?;
            docs.push((label(path), doc));
        }
        merge_attribute_docs(docs)
    }
}

fn label(path: &Path) -> String {
    path.display().to_string()
}

/// Deep-merge a sequence of parsed attribute documents into one tree.
/// Each `doc` is a whole file's parsed YAML (`{ data: { ... } }`); the
/// `String` is a source label used in error messages. Pure and
/// in-memory-testable — [`FileAttributeSource::load`] just reads the
/// files first.
pub fn merge_attribute_docs<I>(docs: I) -> Result<AttributeTree, AttributeError>
where
    I: IntoIterator<Item = (String, Value)>,
{
    let mut acc: Map<String, Value> = Map::new();
    for (label, doc) in docs {
        let data = extract_data(&label, doc)?;
        merge_object(&mut acc, data, "data")?;
    }
    Ok(AttributeTree::new(Value::Object(acc)))
}

/// Pull the `data:` mapping out of one file's parsed document, enforcing
/// the "everything lives under `data:`" contract. An empty file is fine;
/// stray top-level keys (a forgotten `data:` wrapper) are a hard error.
fn extract_data(label: &str, doc: Value) -> Result<Map<String, Value>, AttributeError> {
    match doc {
        Value::Null => Ok(Map::new()),
        Value::Object(mut m) => {
            let data = m.remove("data");
            if !m.is_empty() {
                let mut stray: Vec<String> = m.keys().cloned().collect();
                stray.sort();
                return Err(AttributeError::Parse(format!(
                    "{}: attribute files may only contain a top-level `data:` mapping; \
                     found stray key(s): {}",
                    label,
                    stray.join(", ")
                )));
            }
            match data {
                None | Some(Value::Null) => Ok(Map::new()),
                Some(Value::Object(d)) => Ok(d),
                Some(other) => Err(AttributeError::Parse(format!(
                    "{}: `data:` must be a mapping, got {}",
                    label,
                    type_name(&other)
                ))),
            }
        },
        other => Err(AttributeError::Parse(format!(
            "{}: top-level must be a `data:` mapping, got {}",
            label,
            type_name(&other)
        ))),
    }
}

/// Recursively merge `incoming` into `acc`. Objects merge key-by-key;
/// two different scalars at the same path are a [`AttributeError::Conflict`].
/// Identical values are a no-op (harmless overlap). `prefix` is the dotted
/// path for error context (`data.tenants.acme-eu.data_region`).
fn merge_object(
    acc: &mut Map<String, Value>,
    incoming: Map<String, Value>,
    prefix: &str,
) -> Result<(), AttributeError> {
    for (k, v) in incoming {
        let path = format!("{}.{}", prefix, k);
        if let Some(existing) = acc.get_mut(&k) {
            match (existing, v) {
                (Value::Object(e), Value::Object(iv)) => merge_object(e, iv, &path)?,
                (existing_val, incoming_val) => {
                    if *existing_val != incoming_val {
                        return Err(AttributeError::Conflict {
                            path,
                            existing: existing_val.to_string(),
                            incoming: incoming_val.to_string(),
                        });
                    }
                },
            }
        } else {
            acc.insert(k, v);
        }
    }
    Ok(())
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "mapping",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(label: &str, v: Value) -> (String, Value) {
        (label.to_string(), v)
    }

    #[test]
    fn disjoint_subtrees_combine() {
        let tree = merge_attribute_docs([
            doc("org.yaml", json!({ "data": { "org": { "default_region": "us" } } })),
            doc(
                "tenants.yaml",
                json!({ "data": { "tenants": { "acme-eu": { "data_region": "eu" } } } }),
            ),
        ])
        .unwrap();
        let v = tree.as_value();
        assert_eq!(v.pointer("/org/default_region"), Some(&json!("us")));
        assert_eq!(v.pointer("/tenants/acme-eu/data_region"), Some(&json!("eu")));
    }

    #[test]
    fn nested_objects_deep_merge() {
        // Two files contribute different keys under the same subtree.
        let tree = merge_attribute_docs([
            doc("a.yaml", json!({ "data": { "org": { "region": "us" } } })),
            doc("b.yaml", json!({ "data": { "org": { "tier": "gold" } } })),
        ])
        .unwrap();
        let v = tree.as_value();
        assert_eq!(v.pointer("/org/region"), Some(&json!("us")));
        assert_eq!(v.pointer("/org/tier"), Some(&json!("gold")));
    }

    #[test]
    fn identical_leaf_is_not_a_conflict() {
        let tree = merge_attribute_docs([
            doc("a.yaml", json!({ "data": { "org": { "region": "us" } } })),
            doc("b.yaml", json!({ "data": { "org": { "region": "us" } } })),
        ])
        .unwrap();
        assert_eq!(tree.as_value().pointer("/org/region"), Some(&json!("us")));
    }

    #[test]
    fn conflicting_leaf_fails_fast() {
        let err = merge_attribute_docs([
            doc("a.yaml", json!({ "data": { "org": { "region": "us" } } })),
            doc("b.yaml", json!({ "data": { "org": { "region": "eu" } } })),
        ])
        .unwrap_err();
        match err {
            AttributeError::Conflict {
                path,
                existing,
                incoming,
            } => {
                assert_eq!(path, "data.org.region");
                assert_eq!(existing, "\"us\"");
                assert_eq!(incoming, "\"eu\"");
            },
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    #[test]
    fn object_vs_scalar_at_same_path_conflicts() {
        let err = merge_attribute_docs([
            doc("a.yaml", json!({ "data": { "org": { "region": "us" } } })),
            doc("b.yaml", json!({ "data": { "org": "flat" } })),
        ])
        .unwrap_err();
        assert!(matches!(err, AttributeError::Conflict { .. }));
    }

    #[test]
    fn stray_top_level_key_rejected() {
        // Forgot the `data:` wrapper.
        let err = merge_attribute_docs([doc(
            "oops.yaml",
            json!({ "org": { "region": "us" } }),
        )])
        .unwrap_err();
        match err {
            AttributeError::Parse(msg) => {
                assert!(msg.contains("stray key"), "got: {}", msg);
                assert!(msg.contains("org"), "got: {}", msg);
            },
            other => panic!("expected Parse, got {:?}", other),
        }
    }

    #[test]
    fn empty_and_missing_data_are_ok() {
        let tree = merge_attribute_docs([
            doc("empty.yaml", Value::Null),
            doc("nodata.yaml", json!({ "data": null })),
            doc("real.yaml", json!({ "data": { "org": { "region": "us" } } })),
        ])
        .unwrap();
        assert_eq!(tree.as_value().pointer("/org/region"), Some(&json!("us")));
    }

    #[test]
    fn data_not_a_mapping_rejected() {
        let err = merge_attribute_docs([doc("bad.yaml", json!({ "data": "flat" }))]).unwrap_err();
        assert!(matches!(err, AttributeError::Parse(_)));
    }

    #[test]
    fn load_reads_and_merges_real_files() {
        // Exercise the file-reading path against temp files.
        let dir = std::env::temp_dir().join(format!("apl_attr_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("org.yaml");
        let b = dir.join("tenants.yaml");
        std::fs::write(&a, "data:\n  org:\n    default_region: us\n").unwrap();
        std::fs::write(
            &b,
            "data:\n  tenants:\n    acme-eu:\n      data_region: eu\n",
        )
        .unwrap();

        let src = FileAttributeSource::new([a.clone(), b.clone()]);
        let tree = src.load().unwrap();
        assert_eq!(
            tree.as_value().pointer("/org/default_region"),
            Some(&json!("us"))
        );
        assert_eq!(
            tree.as_value().pointer("/tenants/acme-eu/data_region"),
            Some(&json!("eu"))
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_load_error() {
        let src = FileAttributeSource::new([PathBuf::from("/no/such/attrs.yaml")]);
        assert!(matches!(
            src.load().unwrap_err(),
            AttributeError::Load(_)
        ));
    }
}
