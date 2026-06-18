// Location: ./crates/apl-pdp-cedar-direct/src/template.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `${bag-key}` substitution for `cedar:(...)` step args.
//
// APL authors write Cedar requests like:
//
//     - cedar:
//         action: 'Action::"read"'
//         resource:
//           type: Repo
//           id: ${args.repo_name}
//           attributes:
//             visibility: ${args.visibility}
//             owner_id:   ${subject.id}
//
// This module walks the YAML and rewrites any **scalar string** equal to
// `${<bag-key>}` by reading the value from the `AttributeBag`. Strings
// without the `${...}` wrapper pass through unchanged, so policy authors
// can still write literals like `'Action::"read"'` or `User::"alice"`
// without surprise rewrites.
//
// # Why this looks like template substitution and not magic prefixes
//
// An earlier sketch let bare `args.X` strings substitute implicitly.
// That was load-bearing on a single hardcoded namespace and conflated
// "the author meant a placeholder" with "the author meant a string that
// happens to start with `args.`". The `${...}` form is explicit and
// generalizes to any bag key:
//
//   ${subject.id}        ${subject.type}
//   ${role.engineer}     ${perm.view_ssn}
//   ${claim.email}       ${args.repo_name}     ${args.user.id}
//   ${delegation.granted.audience}             ${meta.entity_name}
//
// The vocabulary mirrors the `MessageView` projection (the bag is
// populated by apl-cmf's `extract_security` / `extract_args` from the
// same source data the view sees), so a Cedar resource template and an
// OPA `input.X` rego path can name the same attribute the same way.
// When (in a separate refactor) `AttributeBag` becomes a derived
// projection of `MessageView`, this substitution layer doesn't change —
// it's already reading the normalized vocabulary.
//
// # What gets substituted
//
//   - Whole-string match: `${args.repo_name}` → value at `args.repo_name`.
//   - Embedded placeholders (`prefix-${args.X}-suffix`) are NOT supported
//     in v0; whole-string only. Easy to extend later, but YAGNI today —
//     Cedar entity IDs / attrs almost always want the raw value.
//   - Missing bag key → loud `PdpError::Dispatch`. Falling back to the
//     literal would mask author bugs.
//   - Mappings + sequences recurse into their members.

use apl_core::attributes::{AttributeBag, AttributeValue};
use apl_core::step::PdpError;

/// Recursively walk `value`, substituting any `${<bag-key>}` scalar with
/// the corresponding bag value. Mappings and sequences recurse. Other
/// scalars pass through unchanged.
pub fn resolve_refs(
    value: &serde_yaml::Value,
    bag: &AttributeBag,
) -> Result<serde_yaml::Value, PdpError> {
    match value {
        serde_yaml::Value::String(s) => {
            if let Some(key) = parse_placeholder(s) {
                substitute(key, s, bag)
            } else {
                Ok(value.clone())
            }
        }
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, v) in map {
                out.insert(k.clone(), resolve_refs(v, bag)?);
            }
            Ok(serde_yaml::Value::Mapping(out))
        }
        serde_yaml::Value::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_refs(item, bag)?);
            }
            Ok(serde_yaml::Value::Sequence(out))
        }
        _ => Ok(value.clone()),
    }
}

/// Return the inner bag key when `s` is exactly `${<key>}` (whole-string
/// placeholder). Returns `None` for any other shape — including
/// `prefix-${args.X}` (embedded), `$args.X` (no braces), or stray `${`
/// without a matching `}`.
fn parse_placeholder(s: &str) -> Option<&str> {
    let inner = s.strip_prefix("${")?.strip_suffix('}')?;
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn substitute(
    key: &str,
    original: &str,
    bag: &AttributeBag,
) -> Result<serde_yaml::Value, PdpError> {
    let value = bag.get(key).ok_or_else(|| {
        PdpError::Dispatch(format!(
            "cedar:() references `{}` but the bag has no key `{}` — \
             check the spelling against the projection vocabulary \
             populated by apl-cmf (security / payload extractors)",
            original, key
        ))
    })?;

    Ok(match value {
        AttributeValue::String(v) => serde_yaml::Value::String(v.clone()),
        AttributeValue::Bool(v) => serde_yaml::Value::Bool(*v),
        AttributeValue::Int(v) => serde_yaml::Value::Number((*v).into()),
        AttributeValue::Float(v) => serde_yaml::Value::Number(serde_yaml::Number::from(*v)),
        AttributeValue::StringSet(set) => {
            let items: Vec<serde_yaml::Value> = set
                .iter()
                .map(|s| serde_yaml::Value::String(s.clone()))
                .collect();
            serde_yaml::Value::Sequence(items)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bag_with(kvs: &[(&str, &str)]) -> AttributeBag {
        let mut bag = AttributeBag::new();
        for (k, v) in kvs {
            bag.set(*k, *v);
        }
        bag
    }

    #[test]
    fn substitutes_args_inside_mapping() {
        let bag = bag_with(&[
            ("args.repo_name", "web-app"),
            ("args.visibility", "internal"),
        ]);
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
type: Repo
id: ${args.repo_name}
attributes:
  visibility: ${args.visibility}
"#,
        )
        .unwrap();

        let resolved = resolve_refs(&yaml, &bag).unwrap();
        let map = resolved.as_mapping().unwrap();
        assert_eq!(
            map.get(serde_yaml::Value::String("id".into()))
                .and_then(|v| v.as_str()),
            Some("web-app")
        );
        let attrs = map
            .get(serde_yaml::Value::String("attributes".into()))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(
            attrs
                .get(serde_yaml::Value::String("visibility".into()))
                .and_then(|v| v.as_str()),
            Some("internal")
        );
    }

    #[test]
    fn substitutes_across_namespaces() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        bag.set("args.repo_name", "core");
        bag.set("claim.email", "alice@corp.com");
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
owner: ${subject.id}
target: ${args.repo_name}
email: ${claim.email}
"#,
        )
        .unwrap();
        let resolved = resolve_refs(&yaml, &bag).unwrap();
        let map = resolved.as_mapping().unwrap();
        assert_eq!(
            map.get(serde_yaml::Value::String("owner".into()))
                .and_then(|v| v.as_str()),
            Some("alice")
        );
        assert_eq!(
            map.get(serde_yaml::Value::String("target".into()))
                .and_then(|v| v.as_str()),
            Some("core")
        );
        assert_eq!(
            map.get(serde_yaml::Value::String("email".into()))
                .and_then(|v| v.as_str()),
            Some("alice@corp.com")
        );
    }

    #[test]
    fn passes_through_literal_strings() {
        let bag = bag_with(&[("args.x", "ignored")]);
        // No `${...}` wrapper → literal.
        let yaml = serde_yaml::Value::String("User::\"alice\"".into());
        let resolved = resolve_refs(&yaml, &bag).unwrap();
        assert_eq!(resolved.as_str(), Some("User::\"alice\""));
        // Even bare `args.x` is now a literal — the explicit `${...}`
        // form is the only thing that triggers substitution.
        let yaml = serde_yaml::Value::String("args.x".into());
        let resolved = resolve_refs(&yaml, &bag).unwrap();
        assert_eq!(resolved.as_str(), Some("args.x"));
    }

    #[test]
    fn missing_bag_key_errors_loudly() {
        let bag = AttributeBag::new();
        let yaml = serde_yaml::Value::String("${args.missing}".into());
        let err = resolve_refs(&yaml, &bag).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("args.missing"),
            "error mentions the key: {}",
            msg
        );
    }

    #[test]
    fn substitutes_typed_values() {
        let mut bag = AttributeBag::new();
        bag.set("args.flag", true);
        bag.set("args.count", 42i64);
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
flag: ${args.flag}
count: ${args.count}
"#,
        )
        .unwrap();
        let resolved = resolve_refs(&yaml, &bag).unwrap();
        let map = resolved.as_mapping().unwrap();
        assert_eq!(
            map.get(serde_yaml::Value::String("flag".into()))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            map.get(serde_yaml::Value::String("count".into()))
                .and_then(|v| v.as_i64()),
            Some(42)
        );
    }

    #[test]
    fn embedded_placeholders_not_supported_in_v0() {
        let bag = bag_with(&[("args.x", "hello")]);
        let yaml = serde_yaml::Value::String("prefix-${args.x}-suffix".into());
        let resolved = resolve_refs(&yaml, &bag).unwrap();
        // Whole-string only — embedded `${...}` is left alone.
        assert_eq!(resolved.as_str(), Some("prefix-${args.x}-suffix"));
    }

    #[test]
    fn empty_placeholder_is_literal() {
        let bag = AttributeBag::new();
        let yaml = serde_yaml::Value::String("${}".into());
        let resolved = resolve_refs(&yaml, &bag).unwrap();
        assert_eq!(resolved.as_str(), Some("${}"));
    }
}
