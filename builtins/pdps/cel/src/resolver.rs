// Location: ./builtins/pdps/cel/src/resolver.rs
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
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use cel::{Context, Program, Value};

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};

use crate::activation::bag_to_context;
use crate::error::BuildError;

/// What to do when an expression errors at runtime (an undeclared
/// variable, a type error, a custom-function panic) or returns a
/// non-boolean value. A `false` result is never affected — it is
/// always a Deny.
///
/// **Compile errors are NOT governed by this enum.** A compile error
/// means an author wrote malformed CEL; there's no legitimate reason
/// to flip that to Allow, so it ALWAYS resolves to Deny + a loud
/// `tracing::error!`. If you flipped a compile error to Allow you'd
/// be silently turning malformed policy into "always allow" — which
/// is a security-hostile default we deliberately don't expose.
/// Cache-full rejections (the cap was hit) are treated as eval errors
/// — they're a runtime resource limit, not an author bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnError {
    /// Fail-closed: a degenerate runtime outcome denies. The APL
    /// default and the safe choice for access decisions.
    #[default]
    Deny,
    /// Fail-open: a degenerate runtime outcome allows through.
    /// Intended for when CEL is a soft/advisory check layered behind a
    /// hard PDP — but **APL does not enforce that layering**. Nothing
    /// stops an operator from making a `cel:` step with `on_error:
    /// allow` the only gate on a route, which turns every runtime error
    /// into an allow. Layering is the operator's responsibility. The
    /// Allow path emits `tracing::error!` (not warn) so runtime errors
    /// masquerading as Allows are not invisible in production logs.
    Allow,
}

/// `PdpResolver` that evaluates CEL boolean expressions. Holds a
/// compile cache so each distinct expression string compiles a single
/// time over the resolver's lifetime.
/// Default upper bound on the compile cache. `cel:` steps are author-
/// supplied in route YAML, so the cache fills with the policy's static
/// set of distinct expressions. 1024 is generous for any realistic
/// policy file and small enough that a templating bug (or a future
/// feature that lets steps build exprs from request data) trips the
/// cap before it can balloon memory.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 1024;

/// A function-registration callback. The host calls
/// [`CelResolver::with_functions`] with one of these and the resolver
/// runs it against the `cel::Context` it builds for every evaluation
/// — registering whatever custom functions the host wants exposed to
/// policy authors. The callback gets full access to clarkmcc's
/// `IntoFunction` magic, so closures can be written in the natural
/// `|s: Arc<String>, n: i64| -> bool` form, not just the raw
/// `&mut FunctionContext` shape.
///
/// The boxed callback is `Send + Sync + 'static` because the resolver
/// is shared across worker threads via `Arc<dyn PdpResolver>` and lives
/// for the process.
pub type CelFunctionSetup = dyn Fn(&mut Context<'static>) + Send + Sync + 'static;

pub struct CelResolver {
    dialect: PdpDialect,
    on_error: OnError,
    /// Upper bound on cached compiled programs. `cache_full` rejects
    /// new entries past this; existing entries are never evicted (per
    /// the workspace-wide "cap + reject + log, never evict" convention,
    /// see `feedback_cache_eviction`).
    max_cache_entries: usize,
    /// Host-supplied custom-function registration callbacks. Each is
    /// invoked on every freshly-built `Context` before evaluation so
    /// expressions can reference the registered names. Multiple
    /// callbacks compose — register e.g. one bundle of regex helpers
    /// and one bundle of time helpers.
    function_setups: Vec<Arc<CelFunctionSetup>>,
    /// Compiled-program cache keyed by expression source. `RwLock` so
    /// the steady-state read-many path (every request hits this once
    /// the route's expr has compiled the first time) is uncontended
    /// — only the rare insert path takes the write lock. APL compiles
    /// route YAML once, so the set of distinct exprs is small and
    /// fixed; concurrent reads dominate the lifecycle.
    cache: RwLock<HashMap<String, Arc<Program>>>,
}

impl CelResolver {
    /// A resolver with default settings (`PdpDialect::Cel`, fail-closed,
    /// cache capped at [`DEFAULT_MAX_CACHE_ENTRIES`]).
    pub fn new() -> Self {
        Self {
            dialect: PdpDialect::Cel,
            on_error: OnError::Deny,
            max_cache_entries: DEFAULT_MAX_CACHE_ENTRIES,
            function_setups: Vec::new(),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Set the error-handling mode (default `Deny`).
    pub fn with_on_error(mut self, on_error: OnError) -> Self {
        self.on_error = on_error;
        self
    }

    /// Override the compile-cache cap (default
    /// [`DEFAULT_MAX_CACHE_ENTRIES`]). Past this bound, new exprs are
    /// rejected at request time and the call is routed through
    /// [`OnError`] — never evict an existing entry. Use this only when
    /// you have hard evidence the default is wrong for your policy size.
    pub fn with_max_cache_entries(mut self, max_cache_entries: usize) -> Self {
        self.max_cache_entries = max_cache_entries;
        self
    }

    /// Register custom CEL functions. The supplied callback is invoked
    /// against every freshly-built evaluation `Context`, so any
    /// `add_function` calls it makes are available to author
    /// expressions on every request.
    ///
    /// Composes: calling `with_functions` more than once stacks the
    /// callbacks. Each runs in registration order on every context.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use cpex_pdp_cel::CelResolver;
    ///
    /// let resolver = CelResolver::new().with_functions(|ctx| {
    ///     // Regex helper — authors can write `args.path.matches_prefix("/api/")`.
    ///     ctx.add_function("matches_prefix",
    ///         |s: Arc<String>, prefix: Arc<String>| -> bool {
    ///             s.starts_with(prefix.as_str())
    ///         });
    ///     // Clock helper — authors can write `now() < session.expires_at`.
    ///     ctx.add_function("now", || -> i64 {
    ///         std::time::SystemTime::now()
    ///             .duration_since(std::time::UNIX_EPOCH)
    ///             .map(|d| d.as_secs() as i64).unwrap_or(0)
    ///     });
    /// });
    /// ```
    ///
    /// Function names that collide with the CEL standard library
    /// (`size`, `has`, `matches`, etc.) silently shadow the built-in
    /// — be deliberate.
    ///
    /// # Ownership of the function set
    ///
    /// The custom-function set is a **host concern**, registered once
    /// when the host wires up the resolver (typically via the
    /// `CelPdpFactory` in the host project), not authored per-route in
    /// policy YAML. The host owns the stable contract of which functions
    /// exist; policy authors only call them. Adding or removing a
    /// function changes that contract for every route at once, so treat
    /// the set like any other host API surface — version it, and avoid
    /// renaming/removing functions that live policies depend on.
    pub fn with_functions<F>(mut self, setup: F) -> Self
    where
        F: Fn(&mut Context<'static>) + Send + Sync + 'static,
    {
        self.function_setups.push(Arc::new(setup));
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
    /// ```
    ///
    /// The actual policy predicate isn't on this block — it's inlined
    /// at each route's `cel: { expr: "..." }` step. Operators who want
    /// to surface bad CEL at *deploy* time rather than at *first
    /// request* should ship a CI smoke test that calls
    /// `load_config_yaml` against their config and exercises one
    /// request per `cel:` step; this resolver doesn't carry an
    /// eager-compile knob of its own.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Self, BuildError> {
        let map = value
            .as_mapping()
            .ok_or_else(|| BuildError::ConfigShape("CEL PDP config must be a mapping".into()))?;

        // Reject unknown keys so a typo (`on_errr: deny`) fails loud at
        // load rather than being silently dropped and defaulting. `kind`
        // is consumed by the visitor/factory but is present on the block;
        // `on_error` is the only knob this resolver reads.
        const KNOWN_KEYS: &[&str] = &["kind", "on_error"];
        for (key, _) in map {
            let Some(name) = key.as_str() else {
                return Err(BuildError::ConfigShape(
                    "CEL PDP config keys must be strings".into(),
                ));
            };
            if !KNOWN_KEYS.contains(&name) {
                return Err(BuildError::ConfigShape(format!(
                    "unknown CEL PDP config key `{name}`; expected one of {KNOWN_KEYS:?}"
                )));
            }
        }

        let on_error = match read_yaml_string(map, "on_error").as_deref() {
            None | Some("deny") => OnError::Deny,
            Some("allow") => OnError::Allow,
            Some(other) => {
                return Err(BuildError::ConfigShape(format!(
                    "`on_error` must be `deny` or `allow`, got `{other}`"
                )));
            }
        };

        Ok(Self::new().with_on_error(on_error))
    }

    /// Get a compiled program for `expr` from the cache, compiling and
    /// caching it on first use.
    ///
    /// Read-many fast path under the `RwLock` (uncontended once the
    /// route's expr has compiled); first-miss falls through to the
    /// write lock to compile + insert. APL compiles all routes at
    /// `load_config_yaml` time — single-threaded — so the realistic
    /// race window is zero. A duplicate concurrent compile would
    /// merely overwrite an equivalent entry and drop the loser's
    /// `Arc`, so no extra double-checked-locking machinery is
    /// warranted here.
    ///
    /// Cap enforcement: at `max_cache_entries` the next *new* expr is
    /// rejected with `CacheFull`. The caller treats it as a degenerate
    /// outcome and routes through [`OnError`]. Existing entries are
    /// never evicted.
    fn get_or_compile(&self, expr: &str) -> Result<Arc<Program>, GetOrCompileError> {
        if let Some(program) = self
            .cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(expr)
        {
            return Ok(Arc::clone(program));
        }
        let program = Arc::new(
            Program::compile(expr).map_err(|e| GetOrCompileError::Compile(e.to_string()))?,
        );
        let mut cache = self.cache.write().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= self.max_cache_entries && !cache.contains_key(expr) {
            tracing::warn!(
                cap = self.max_cache_entries,
                "CEL compile cache full; rejecting new expression. Existing entries are not \
                 evicted. Increase `with_max_cache_entries` if your policy legitimately exceeds \
                 the default bound."
            );
            return Err(GetOrCompileError::CacheFull {
                cap: self.max_cache_entries,
            });
        }
        cache.insert(expr.to_string(), Arc::clone(&program));
        Ok(program)
    }

    /// Apply the `on_error` policy to a degenerate RUNTIME outcome
    /// (eval error, non-boolean result, cache-full rejection),
    /// producing a `PdpDecision` with the cause recorded in
    /// diagnostics. Allow uses `tracing::error!` (not warn) so an
    /// operator misusing the flag sees it loudly in production logs.
    ///
    /// Compile errors do NOT come through here — see
    /// [`Self::compile_error_decision`].
    fn on_error_decision(&self, cause: String) -> PdpDecision {
        match self.on_error {
            OnError::Allow => {
                tracing::error!(
                    cause = %cause,
                    "CEL runtime error; on_error=allow → allowing through. \
                     This is fail-open behavior; verify it is intentional."
                );
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

    /// Compile errors always fail closed — a malformed `expr` is an
    /// author bug, not a runtime condition, and silently flipping it
    /// to Allow would let broken policy bypass the gate. Logs at
    /// `error!` so the operator notices in CI / production.
    fn compile_error_decision(&self, cause: String) -> PdpDecision {
        tracing::error!(
            cause = %cause,
            "CEL compile error — author-supplied expression failed to parse. \
             Denying request regardless of on_error mode."
        );
        PdpDecision {
            decision: Decision::Deny {
                reason: Some(cause.clone()),
                rule_source: "cel".to_string(),
            },
            diagnostics: vec![cause],
        }
    }
}

impl Default for CelResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal — failure shapes from `get_or_compile`. Folds into
/// `on_error_decision` at the eval call site; not part of the public
/// surface.
enum GetOrCompileError {
    Compile(String),
    CacheFull { cap: usize },
}

impl std::fmt::Display for GetOrCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compile(e) => write!(f, "CEL compile error: {e}"),
            Self::CacheFull { cap } => write!(
                f,
                "CEL compile-cache full (cap={cap}); refusing to compile a new expression. \
                 Bump `with_max_cache_entries` if the policy legitimately needs more, otherwise \
                 investigate a templating or generation bug producing unbounded distinct exprs."
            ),
        }
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

        // 2. Compile (cached). Compile errors always Deny (an author
        //    bug, never legitimately flippable). Cache-full rejections
        //    are runtime conditions and route through on_error.
        let program = match self.get_or_compile(expr) {
            Ok(p) => p,
            Err(e @ GetOrCompileError::Compile(_)) => {
                return Ok(self.compile_error_decision(e.to_string()));
            }
            Err(e @ GetOrCompileError::CacheFull { .. }) => {
                return Ok(self.on_error_decision(e.to_string()));
            }
        };

        // 3. Build the activation from the bag + author-supplied extra
        //    args. Then layer any host-supplied custom-function bundles
        //    on top so expressions can call into them. Setups run in
        //    registration order; later setups can shadow earlier ones,
        //    which is the documented contract.
        let mut ctx = bag_to_context(bag, &call.args);
        for setup in &self.function_setups {
            setup(&mut ctx);
        }

        // 4. Evaluate and map the result to a decision.
        match program.execute(&ctx) {
            Ok(Value::Bool(true)) => Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: vec![],
            }),
            Ok(Value::Bool(false)) => {
                // Enrich the deny diagnostics with a snapshot of the
                // bag values the expression actually references, so an
                // auditor can see WHY without re-running with debug
                // logging. Bounded — a typical predicate touches 2-5
                // namespaces.
                let mut diagnostics = vec![format!("cel: {expr}")];
                diagnostics.extend(snapshot_referenced_bag_values(&program, bag));
                Ok(PdpDecision {
                    decision: Decision::Deny {
                        reason: Some("CEL expression evaluated to false".to_string()),
                        rule_source: "cel".to_string(),
                    },
                    diagnostics,
                })
            }
            Ok(other) => Ok(self.on_error_decision(format!(
                "CEL expression must return bool, got {other:?}"
            ))),
            Err(e) => {
                // Eval errors are usually undeclared-variable typos.
                // Enumerate the variables the expression references AND
                // which ones the bag actually has, so the operator can
                // see which name they meant.
                let mut cause = format!("CEL eval error: {e}");
                let refs = program.references();
                let referenced: Vec<&str> = refs.variables();
                if !referenced.is_empty() {
                    let mut found = referenced
                        .iter()
                        .filter(|n| bag_namespace_present(bag, n))
                        .copied()
                        .collect::<Vec<_>>();
                    found.sort_unstable();
                    let mut missing = referenced
                        .iter()
                        .filter(|n| !bag_namespace_present(bag, n))
                        .copied()
                        .collect::<Vec<_>>();
                    missing.sort_unstable();
                    cause.push_str(&format!(
                        " (expr references variables: {referenced:?}; \
                         present in bag: {found:?}; missing: {missing:?})"
                    ));
                }
                Ok(self.on_error_decision(cause))
            }
        }
    }
}

/// Snapshot all bag entries whose dotted-key first segment matches any
/// of the top-level names the CEL expression references. Emits one
/// diagnostic string per matched key in `key=value` form. Used to
/// enrich Deny diagnostics so auditors can see what made the predicate
/// false without re-running with debug logging.
fn snapshot_referenced_bag_values(
    program: &Program,
    bag: &AttributeBag,
) -> Vec<String> {
    let refs = program.references();
    let referenced = refs.variables();
    if referenced.is_empty() {
        return Vec::new();
    }
    let referenced_set: std::collections::HashSet<&str> =
        referenced.iter().copied().collect();

    let mut snapshot: Vec<String> = bag
        .iter()
        .filter(|(key, _)| {
            let head = key.split('.').next().unwrap_or(key);
            referenced_set.contains(head)
        })
        .map(|(key, value)| format!("{key}={value:?}"))
        .collect();
    snapshot.sort_unstable();
    snapshot
}

/// Does the bag have any key whose dotted-prefix first segment matches
/// `name`? Used to classify referenced variables as present-or-missing
/// in eval-error diagnostics.
fn bag_namespace_present(bag: &AttributeBag, name: &str) -> bool {
    bag.iter().any(|(key, _)| {
        let head: &str = key.split('.').next().unwrap_or(key);
        head == name
    })
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

    /// A host can register a custom CEL function via `with_functions`
    /// and expressions can call it. Registration composes: a second
    /// `with_functions` call stacks on top of the first.
    #[tokio::test]
    async fn custom_function_registration_round_trips() {
        let r = CelResolver::new()
            .with_functions(|ctx| {
                ctx.add_function(
                    "double",
                    |n: i64| -> i64 { n * 2 },
                );
            })
            .with_functions(|ctx| {
                ctx.add_function(
                    "shout",
                    |s: Arc<String>| -> String { s.to_uppercase() },
                );
            });
        let bag = bag_with(&[("subject.id", "alice")]);

        // First registered function works.
        let out = r.evaluate(&cel_call("double(21) == 42"), &bag).await.unwrap();
        assert_eq!(
            out.decision, Decision::Allow,
            "first registered function must be callable",
        );

        // Second composed function works (and reads a bag value).
        let out = r
            .evaluate(&cel_call("shout(subject.id) == 'ALICE'"), &bag)
            .await
            .unwrap();
        assert_eq!(
            out.decision, Decision::Allow,
            "subsequent with_functions calls must compose, not replace",
        );
    }

    /// The `regex` cel-feature is explicitly enabled in our Cargo.toml.
    /// Pin that `matches(s, pattern)` actually works through the
    /// resolver so a future feature-set churn breaks loudly here.
    #[tokio::test]
    async fn matches_regex_function_is_available() {
        let r = CelResolver::new();
        let bag = bag_with(&[("args.path", "/api/v1/tools/call")]);
        let out = r
            .evaluate(&cel_call("args.path.matches('^/api/v[0-9]+/')"), &bag)
            .await
            .unwrap();
        assert_eq!(
            out.decision, Decision::Allow,
            "the regex CEL feature must be enabled so authors can match paths",
        );
    }

    #[tokio::test]
    async fn undeclared_variable_fails_closed_by_default() {
        let r = CelResolver::new();
        // `nonexistent` is not in the bag → eval error → fail-closed Deny.
        let out = r.evaluate(&cel_call("nonexistent.field == 1"), &AttributeBag::new()).await.unwrap();
        assert!(matches!(out.decision, Decision::Deny { .. }));
    }

    /// On Deny, diagnostics include a snapshot of the bag values for
    /// every top-level namespace the expression references. Auditors
    /// reading the diagnostics see WHY the predicate evaluated false
    /// without re-running with debug logging.
    #[tokio::test]
    async fn deny_diagnostics_snapshot_referenced_bag_values() {
        let r = CelResolver::new();
        let bag = bag_with(&[
            ("subject.id", "eve"),
            ("subject.type", "user"),
            ("unrelated.key", "ignore-me"),
        ]);
        let out = r
            .evaluate(&cel_call("subject.id == 'alice'"), &bag)
            .await
            .unwrap();
        assert!(matches!(out.decision, Decision::Deny { .. }));
        let snapshot = out
            .diagnostics
            .iter()
            .find(|d| d.contains("subject.id="))
            .unwrap_or_else(|| panic!("expected subject.id snapshot; got {:?}", out.diagnostics));
        assert!(
            snapshot.contains("\"eve\""),
            "snapshot must carry the actual bag value; got {snapshot:?}",
        );
        // Unrelated namespaces stay out — keeps the diagnostic bounded.
        assert!(
            !out.diagnostics.iter().any(|d| d.contains("unrelated")),
            "snapshot must be scoped to referenced namespaces; got {:?}",
            out.diagnostics,
        );
    }

    /// On an eval error (undeclared variable), the cause string lists
    /// the referenced variables AND classifies them present-vs-missing
    /// in the bag, so the operator can see which typo they made.
    #[tokio::test]
    async fn eval_error_diagnostics_classify_referenced_variables() {
        let r = CelResolver::new();
        let bag = bag_with(&[("subject.id", "alice")]);
        // `subjcet` is a typo for `subject` — eval error, fail-closed.
        let out = r
            .evaluate(&cel_call("subjcet.id == 'alice'"), &bag)
            .await
            .unwrap();
        let cause = match out.decision {
            Decision::Deny { reason, .. } => reason.unwrap_or_default(),
            other => panic!("expected Deny; got {other:?}"),
        };
        assert!(
            cause.contains("missing: [\"subjcet\"]"),
            "cause must classify the typo as missing; got {cause:?}",
        );
    }

    /// A malformed `expr` always Denies, even with `on_error: allow`.
    /// Compile errors are author bugs — silently flipping them to Allow
    /// would let broken policy bypass the gate. Pins the asymmetry
    /// between compile errors and runtime errors.
    #[tokio::test]
    async fn compile_error_always_denies_even_with_on_error_allow() {
        let r = CelResolver::new().with_on_error(OnError::Allow);
        // `1 +` is a syntax error → compile failure → unconditional Deny.
        let out = r.evaluate(&cel_call("1 +"), &AttributeBag::new()).await.unwrap();
        match out.decision {
            Decision::Deny { reason, rule_source } => {
                assert_eq!(rule_source, "cel");
                let r = reason.unwrap_or_default();
                assert!(
                    r.contains("compile error"),
                    "deny reason must name the compile failure; got {r:?}",
                );
            }
            other => panic!("compile error must deny regardless of on_error; got {other:?}"),
        }
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
        let cache = r.cache.read().unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(expr));
    }

    /// At the cache cap, the *next new* expr is rejected — but already-
    /// cached exprs still evaluate normally. The rejected call is routed
    /// through `on_error` (default Deny), so policy still gets a
    /// decision even when the operator's cap is too tight.
    #[tokio::test]
    async fn cache_cap_rejects_new_exprs_but_keeps_old_ones() {
        let r = CelResolver::new().with_max_cache_entries(1);
        let bag = bag_with(&[("subject.id", "alice")]);

        // First expr fills the cache.
        let first = r.evaluate(&cel_call("subject.id == 'alice'"), &bag).await.unwrap();
        assert_eq!(first.decision, Decision::Allow);
        assert_eq!(r.cache.read().unwrap().len(), 1);

        // Second distinct expr → rejected by the cap → on_error Deny.
        let second = r.evaluate(&cel_call("subject.id != ''"), &bag).await.unwrap();
        assert!(
            matches!(second.decision, Decision::Deny { .. }),
            "cap rejection must route through on_error Deny by default",
        );
        assert!(
            second.diagnostics.iter().any(|d| d.contains("cache full")),
            "rejection diagnostic must name the cause; got {:?}",
            second.diagnostics,
        );
        assert_eq!(
            r.cache.read().unwrap().len(),
            1,
            "rejected expr must not be inserted",
        );

        // Cached expr still works.
        let third = r.evaluate(&cel_call("subject.id == 'alice'"), &bag).await.unwrap();
        assert_eq!(third.decision, Decision::Allow);
    }

    /// `on_error: allow` flips a cache-full rejection to Allow — same
    /// path as compile / eval errors. Pins that the fail-open knob is
    /// uniform across all degenerate outcomes.
    #[tokio::test]
    async fn cache_cap_respects_on_error_allow() {
        let r = CelResolver::new()
            .with_max_cache_entries(1)
            .with_on_error(OnError::Allow);
        let bag = bag_with(&[("subject.id", "alice")]);

        // Fill the cache.
        let _ = r.evaluate(&cel_call("subject.id == 'alice'"), &bag).await.unwrap();

        // Second distinct expr is cap-rejected → on_error Allow.
        let out = r.evaluate(&cel_call("subject.id != ''"), &bag).await.unwrap();
        assert_eq!(out.decision, Decision::Allow);
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

    /// An unknown config key (here `on_errr`, a typo for `on_error`) is
    /// rejected at config-parse time rather than silently dropped — a
    /// dropped key would mask the typo and use the default `Deny`,
    /// leaving the operator believing they'd set `allow`. The error
    /// names the offending key.
    #[test]
    fn from_config_rejects_unknown_key() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("kind: cel\non_errr: allow\n").unwrap();
        match CelResolver::from_config(&yaml) {
            Err(BuildError::ConfigShape(msg)) => assert!(
                msg.contains("on_errr"),
                "error must name the unknown key; got {msg:?}",
            ),
            Ok(_) => panic!("unknown key `on_errr` must be rejected"),
        }
    }

    /// Many threads evaluating the same expression on one shared
    /// resolver must all get the right decision, and the compile cache
    /// must hold exactly one entry (the `RwLock` read path is
    /// uncontended in steady state; this pins that concurrent reads
    /// don't double-insert or deadlock).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_evaluation_shares_one_cached_program() {
        let resolver = Arc::new(CelResolver::new());
        let expr = "subject.id == 'alice'";

        let tasks: Vec<_> = (0..64)
            .map(|i| {
                let r = Arc::clone(&resolver);
                tokio::spawn(async move {
                    // Half match, half don't — exercises both Allow and
                    // Deny through the shared cache concurrently.
                    let id = if i % 2 == 0 { "alice" } else { "bob" };
                    let bag = bag_with(&[("subject.id", id)]);
                    let out = r.evaluate(&cel_call(expr), &bag).await.unwrap();
                    (id, out.decision)
                })
            })
            .collect();

        for task in tasks {
            let (id, decision) = task.await.unwrap();
            if id == "alice" {
                assert_eq!(decision, Decision::Allow);
            } else {
                assert!(matches!(decision, Decision::Deny { .. }));
            }
        }

        // One distinct expr → exactly one compiled program despite the
        // concurrent first-miss race.
        let cache = resolver.cache.read().unwrap();
        assert_eq!(cache.len(), 1, "concurrent compiles must converge to one entry");
        assert!(cache.contains_key(expr));
    }
}
