// Location: ./crates/apl-pdp-cel/src/resolver.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CelResolver` — the `PdpResolver` implementation. Compiles each distinct
// `cel: { expr: "..." }` expression once (cached by source string) and
// evaluates it against the policy `AttributeBag` on every call.
//
// # Decision contract
//
//   - expression → `true`   → Allow
//   - expression → `false`  → Deny  (a legitimate policy denial; always honored)
//   - non-boolean result, undeclared-variable reference, or any other
//     evaluation error → governed by `on_error` (default `Deny`, i.e.
//     fail-closed). `on_error: allow` flips these degenerate cases to Allow.
//   - a `cel:` step with no `expr` string is a config bug → `PdpError`.
//
// The cause of any Deny / error is recorded in `PdpDecision.diagnostics`
// for audit, and is the `rule_source` on the resulting Deny.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cel::{Program, Value};

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};

use crate::activation::bag_to_context;
use crate::error::BuildError;

/// What to do when an expression fails to compile, errors at runtime
/// (e.g. references an undeclared variable), or returns a non-boolean.
/// A `false` result is never affected — it is always a Deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnError {
    /// Fail-closed: a degenerate expression denies. The APL default and
    /// the safe choice for access decisions.
    #[default]
    Deny,
    /// Fail-open: a degenerate expression allows through. Use only when
    /// CEL is a soft/advisory check layered behind a hard PDP.
    Allow,
}

/// `PdpResolver` that evaluates CEL boolean expressions. Holds a
/// compile cache so each distinct expression string compiles a single
/// time over the resolver's lifetime.
pub struct CelResolver {
    dialect: PdpDialect,
    on_error: OnError,
    /// Compiled-program cache keyed by expression source. Write-once per
    /// expr; a `Mutex` is plenty (no contention of note — APL compiles
    /// route YAML once, so the set of distinct exprs is small and fixed).
    cache: Mutex<HashMap<String, Arc<Program>>>,
}

impl CelResolver {
    /// A resolver with default settings (`PdpDialect::Cel`, fail-closed).
    pub fn new() -> Self {
        Self {
            dialect: PdpDialect::Cel,
            on_error: OnError::Deny,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Set the error-handling mode (default `Deny`).
    pub fn with_on_error(mut self, on_error: OnError) -> Self {
        self.on_error = on_error;
        self
    }

    /// Override the resolver's dialect. Lets operators register a CEL
    /// engine under a custom name so two CEL resolvers (e.g. different
    /// `on_error` modes) can coexist on one `PdpRouter`.
    pub fn with_dialect(mut self, dialect: PdpDialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Build a resolver from a unified-config block. Shape:
    ///
    /// ```yaml
    /// kind: cel              # matched by the factory, not read here
    /// on_error: deny         # optional; deny | allow, default deny
    /// expr: |                # optional default expression — if present,
    ///   subject.id != ""     #   compiled eagerly so typos surface at load
    /// ```
    ///
    /// `expr` here is only a config-level *default*/validation aid; the
    /// authoritative expression is the one each route's `cel:` step
    /// supplies at call time.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Self, BuildError> {
        let map = value
            .as_mapping()
            .ok_or_else(|| BuildError::ConfigShape("CEL PDP config must be a mapping".into()))?;

        let on_error = match read_yaml_string(map, "on_error").as_deref() {
            None | Some("deny") => OnError::Deny,
            Some("allow") => OnError::Allow,
            Some(other) => {
                return Err(BuildError::ConfigShape(format!(
                    "`on_error` must be `deny` or `allow`, got `{}`",
                    other
                )));
            }
        };

        let resolver = Self::new().with_on_error(on_error);

        // Eagerly compile + cache an optional config-level default expr so
        // a typo is reported at load rather than first request.
        if let Some(expr) = read_yaml_string(map, "expr") {
            let program = Program::compile(&expr)
                .map_err(|e| BuildError::ExprCompile(e.to_string()))?;
            resolver
                .cache
                .lock()
                .expect("cel compile cache mutex poisoned")
                .insert(expr, Arc::new(program));
        }

        Ok(resolver)
    }

    /// Get a compiled program for `expr` from the cache, compiling and
    /// caching it on first use.
    fn get_or_compile(&self, expr: &str) -> Result<Arc<Program>, String> {
        let mut cache = self.cache.lock().expect("cel compile cache mutex poisoned");
        if let Some(program) = cache.get(expr) {
            return Ok(Arc::clone(program));
        }
        let program = Program::compile(expr).map_err(|e| e.to_string())?;
        let program = Arc::new(program);
        cache.insert(expr.to_string(), Arc::clone(&program));
        Ok(program)
    }

    /// Apply the `on_error` policy to a degenerate outcome, producing a
    /// `PdpDecision` with the cause recorded in diagnostics.
    fn on_error_decision(&self, cause: String) -> PdpDecision {
        match self.on_error {
            OnError::Allow => {
                tracing::warn!(cause = %cause, "CEL eval error; on_error=allow → allowing through");
                PdpDecision { decision: Decision::Allow, diagnostics: vec![cause] }
            }
            OnError::Deny => PdpDecision {
                decision: Decision::Deny {
                    reason: Some(cause.clone()),
                    rule_source: "cel".to_string(),
                },
                diagnostics: vec![cause],
            },
        }
    }
}

impl Default for CelResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PdpResolver for CelResolver {
    fn dialect(&self) -> PdpDialect {
        self.dialect.clone()
    }

    async fn evaluate(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        // 1. Pull the expression text from the step args. A `cel:` step
        //    with no `expr` string is an author/config bug — hard error.
        let expr = call
            .args
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("expr".into())))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PdpError::Dispatch(
                    "cel:() step requires a string `expr` argument".to_string(),
                )
            })?;

        // 2. Compile (cached) — a compile failure is governed by on_error.
        let program = match self.get_or_compile(expr) {
            Ok(p) => p,
            Err(e) => {
                return Ok(self.on_error_decision(format!("CEL compile error: {}", e)));
            }
        };

        // 3. Build the activation from the bag + author-supplied extra args.
        let ctx = bag_to_context(bag, &call.args);

        // 4. Evaluate and map the result to a decision.
        match program.execute(&ctx) {
            Ok(Value::Bool(true)) => Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: vec![],
            }),
            Ok(Value::Bool(false)) => Ok(PdpDecision {
                decision: Decision::Deny {
                    reason: Some("CEL expression evaluated to false".to_string()),
                    rule_source: "cel".to_string(),
                },
                diagnostics: vec![format!("cel: {}", expr)],
            }),
            Ok(other) => Ok(self.on_error_decision(format!(
                "CEL expression must return bool, got {:?}",
                other
            ))),
            Err(e) => Ok(self.on_error_decision(format!("CEL eval error: {}", e))),
        }
    }
}

/// Read a string field from a YAML mapping (mirrors the cedar-direct helper).
fn read_yaml_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_string()))?
        .as_str()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cel_call(expr: &str) -> PdpCall {
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("expr".into()),
            serde_yaml::Value::String(expr.into()),
        );
        PdpCall {
            dialect: PdpDialect::Cel,
            args: serde_yaml::Value::Mapping(m),
        }
    }

    fn bag_with(pairs: &[(&str, &str)]) -> AttributeBag {
        let mut bag = AttributeBag::new();
        for (k, v) in pairs {
            bag.set(*k, *v);
        }
        bag
    }

    #[tokio::test]
    async fn true_allows_false_denies() {
        let r = CelResolver::new();
        let bag = bag_with(&[("subject.id", "alice")]);

        let allow = r.evaluate(&cel_call("subject.id == 'alice'"), &bag).await.unwrap();
        assert_eq!(allow.decision, Decision::Allow);

        let deny = r.evaluate(&cel_call("subject.id == 'bob'"), &bag).await.unwrap();
        assert!(matches!(deny.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn missing_expr_is_dispatch_error() {
        let r = CelResolver::new();
        let call = PdpCall {
            dialect: PdpDialect::Cel,
            args: serde_yaml::Value::Null,
        };
        let err = r.evaluate(&call, &AttributeBag::new()).await.unwrap_err();
        assert!(matches!(err, PdpError::Dispatch(_)));
    }

    #[tokio::test]
    async fn undeclared_variable_fails_closed_by_default() {
        let r = CelResolver::new();
        // `nonexistent` is not in the bag → eval error → fail-closed Deny.
        let out = r.evaluate(&cel_call("nonexistent.field == 1"), &AttributeBag::new()).await.unwrap();
        assert!(matches!(out.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn on_error_allow_flips_eval_error_to_allow() {
        let r = CelResolver::new().with_on_error(OnError::Allow);
        let out = r.evaluate(&cel_call("nonexistent.field == 1"), &AttributeBag::new()).await.unwrap();
        assert_eq!(out.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn non_boolean_result_fails_closed() {
        let r = CelResolver::new();
        let bag = bag_with(&[("subject.id", "alice")]);
        // Returns a string, not a bool → degenerate → fail-closed Deny.
        let out = r.evaluate(&cel_call("subject.id"), &bag).await.unwrap();
        assert!(matches!(out.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn compile_cache_reuses_program() {
        let r = CelResolver::new();
        let bag = bag_with(&[("subject.id", "alice")]);
        let expr = "subject.id == 'alice'";
        let _ = r.evaluate(&cel_call(expr), &bag).await.unwrap();
        let _ = r.evaluate(&cel_call(expr), &bag).await.unwrap();
        // One distinct expr → exactly one cached program (compiled once).
        let cache = r.cache.lock().unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(expr));
    }

    #[test]
    fn from_config_parses_on_error() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("kind: cel\non_error: allow\n").unwrap();
        let r = CelResolver::from_config(&yaml).unwrap();
        assert_eq!(r.on_error, OnError::Allow);
    }

    #[test]
    fn from_config_rejects_bad_on_error() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("kind: cel\non_error: maybe\n").unwrap();
        assert!(matches!(
            CelResolver::from_config(&yaml),
            Err(BuildError::ConfigShape(_))
        ));
    }

    #[test]
    fn from_config_eagerly_compiles_default_expr() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("kind: cel\nexpr: \"1 == 1\"\n").unwrap();
        let r = CelResolver::from_config(&yaml).unwrap();
        assert_eq!(r.cache.lock().unwrap().len(), 1);

        // A broken default expr is reported at construction.
        let bad: serde_yaml::Value =
            serde_yaml::from_str("kind: cel\nexpr: \"1 +\"\n").unwrap();
        assert!(matches!(
            CelResolver::from_config(&bad),
            Err(BuildError::ExprCompile(_))
        ));
    }
}
