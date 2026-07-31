// Location: ./builtins/pdps/opa/src/resolver.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// `OpaResolver` — the `PdpResolver` implementation over regorus.
//
// # Build once, evaluate many
//
// `from_config` prepares a base `regorus::Engine` at factory-build time: it
// parses every global Rego module and loads every `data` document a single
// time. Because regorus (with the `arc` feature) reference-counts its compiled
// policy and data behind atomic `Arc`, cloning the base engine is cheap and
// shares that compiled state. Every `evaluate` call therefore clones the base,
// sets the request `input`, and evaluates — no lock on the hot path, no
// re-parse. (All regorus `set_input`/`eval_*` methods take `&mut self`, so a
// per-request clone is what makes concurrent evaluation possible at all.)
//
// Clone-per-request is input-isolated by regorus contract, not by luck.
// `Interpreter::clone` resets the rule-value and builtin memo maps to empty, and
// `Engine::eval_rule` calls `clean_internal_evaluation_state()` before every
// evaluation, clearing those maps plus `data` and the scope stack. A regorus
// change to either would break input isolation, so `concurrent_evaluation_is_correct`
// and `sequential_reuse_does_not_leak_prior_input` pin the observable behavior.
//
// Inline `opa: { module: "..." }` steps get their own bounded cache of
// prepared engines (base + that module), so a distinct inline module is parsed
// at most once. The cache follows the workspace "cap + reject + log, never
// evict" convention.
//
// # Inline-module trust boundary
//
// A route-step inline module and the operator's global modules are both
// operator-authored config, but they can be edited by different parties (a
// central security team owns `global.pdp`; an app team may own a route). To
// keep an inline module from silently overriding operator policy, an inline
// module whose Rego package collides with a global-module package is rejected
// fail-closed (always deny) rather than merged. Inline modules may therefore
// *add* new packages but cannot redefine or extend a global package's rules.
// (Global modules still merge with each other per Rego package semantics —
// they share one trust level.)
//
// # Decision contract
//
// The configured query must resolve to a boolean, a decision object, or a
// set/array (see `crate::decision`). Fail-closed by default: an evaluation
// error routes through `on_error` (default `Deny`); a Rego parse error, an
// inline/global package collision, and a cache-full rejection always deny
// regardless of `on_error` (a compile-time or resource condition must never
// fail open).

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;
use regorus::Engine;

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};

use crate::decision::{map_query_result, Mapped};
use crate::error::BuildError;
use crate::input::bag_to_input;

/// What to do when a query errors at runtime or yields a value that carries no
/// decision (a non-bool/object/set result, or a missing decision field). A
/// `false`/deny result and an undefined result are NOT governed by this — they
/// are legitimate denials, always honored. Parse/compile errors, inline/global
/// package collisions, and cache-full rejections are never governed by this
/// either: they always deny (an author bug, a trust-boundary violation, or a
/// resource limit must never flip to allow). Mirrors `cpex-pdp-cel`'s `OnError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnError {
    /// Fail-closed: a degenerate runtime outcome denies. The APL default.
    #[default]
    Deny,
    /// Fail-open: a degenerate runtime outcome allows through. For advisory
    /// checks layered behind a hard PDP; the resolver logs at `error!` on this
    /// path so it is never silent.
    Allow,
}

/// Default upper bound on the inline-module cache. Inline modules are
/// author-supplied in route YAML, so the cache fills with the policy's static
/// set of distinct inline modules. 1024 is generous for any realistic policy
/// and small enough that a templating bug trips the cap before it balloons
/// memory. Mirrors `cpex-pdp-cel`'s cache cap.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 1024;

/// Virtual filename regorus uses for the query's inline module. Distinct from
/// the `global-<n>.rego` names global modules load under, so an inline module
/// adds to the engine rather than replacing a global one.
pub(crate) const INLINE_MODULE_NAME: &str = "__inline__.rego";

#[derive(Debug)]
pub struct OpaResolver {
    dialect: PdpDialect,
    on_error: OnError,
    /// The object field (or, for a set/array result, ignored) that carries the
    /// allow/deny boolean when the query resolves to an object. Default
    /// `"allow"`.
    decision_field: String,
    /// The base engine, prepared once with all global modules + data. Cloned
    /// per request (cheap — compiled policy/data is `Arc`-shared).
    base_engine: Engine,
    /// Rego package paths declared by the global modules (e.g. `data.authz`),
    /// captured at build. A route-step inline module whose package is in this
    /// set is rejected fail-closed so it cannot override operator policy.
    global_packages: HashSet<String>,
    /// Cache of prepared engines for inline modules, keyed by module source.
    /// `RwLock` so the steady-state read path is uncontended once a route's
    /// inline module has been prepared.
    inline_cache: RwLock<HashMap<String, Engine>>,
    /// Upper bound on `inline_cache`. New entries past this are rejected (never
    /// evicted), per the workspace cache convention.
    max_cache_entries: usize,
}

impl OpaResolver {
    /// Build a resolver from a unified-config block. Shape:
    ///
    /// ```yaml
    /// kind: opa                 # matched by the factory, not read here
    /// on_error: deny            # optional; deny | allow, default deny
    /// decision_field: allow     # optional; object field holding the bool, default "allow"
    /// modules:                  # optional; inline Rego module texts
    ///   - |
    ///     package authz
    ///     default allow := false
    ///     allow if input.subject.id == "alice"
    /// module_files:             # optional; paths to Rego module files
    ///   - policies/authz.rego
    /// data:                     # optional; inline data merged into the `data` root
    ///   roles:
    ///     alice: [reader]
    /// data_files:               # optional; paths to JSON/YAML data files
    ///   - data/roles.json
    /// max_cache_entries: 1024   # optional; cap on distinct inline modules,
    ///                           # default 1024. 0 disables inline modules (a
    ///                           # step carrying one denies); global-module
    ///                           # steps are unaffected.
    /// ```
    ///
    /// Global modules and data are parsed/loaded here, once. A Rego parse error
    /// or a data merge conflict surfaces as a `BuildError` at load time.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Self, BuildError> {
        let map = value
            .as_mapping()
            .ok_or_else(|| BuildError::ConfigShape("OPA PDP config must be a mapping".into()))?;

        // Reject unknown keys so a typo fails loud at load rather than being
        // silently dropped. `kind` is consumed by the factory but present here.
        const KNOWN_KEYS: &[&str] = &[
            "kind",
            "on_error",
            "decision_field",
            "modules",
            "module_files",
            "data",
            "data_files",
            "max_cache_entries",
        ];
        for (key, _) in map {
            let Some(name) = key.as_str() else {
                return Err(BuildError::ConfigShape(
                    "OPA PDP config keys must be strings".into(),
                ));
            };
            if !KNOWN_KEYS.contains(&name) {
                return Err(BuildError::ConfigShape(format!(
                    "unknown OPA PDP config key `{name}`; expected one of {KNOWN_KEYS:?}"
                )));
            }
        }

        let on_error = match read_string(map, "on_error")?.as_deref() {
            None | Some("deny") => OnError::Deny,
            Some("allow") => OnError::Allow,
            Some(other) => {
                return Err(BuildError::ConfigShape(format!(
                    "`on_error` must be `deny` or `allow`, got `{other}`"
                )));
            },
        };

        let decision_field = read_string(map, "decision_field")?.unwrap_or_else(|| "allow".into());

        let mut engine = Engine::new();
        // Track each global module's Rego package (the path `add_policy`
        // returns) so an inline step module can be rejected if it collides.
        let mut global_packages = HashSet::new();

        // 1. Global modules — inline texts first, then files. Each gets a
        //    unique virtual name so same-package modules merge (Rego
        //    semantics) rather than one overwriting another by filename.
        for (module_index, text) in read_string_seq(map, "modules")?.into_iter().enumerate() {
            let name = format!("global-{module_index}.rego");
            let package =
                engine
                    .add_policy(name.clone(), text)
                    .map_err(|e| BuildError::ModuleParse {
                        name,
                        cause: e.to_string(),
                    })?;
            global_packages.insert(package);
        }
        for path in read_string_seq(map, "module_files")? {
            let text = std::fs::read_to_string(&path).map_err(|source| BuildError::ModuleFile {
                path: path.clone(),
                source,
            })?;
            let package =
                engine
                    .add_policy(path.clone(), text)
                    .map_err(|e| BuildError::ModuleParse {
                        name: path,
                        cause: e.to_string(),
                    })?;
            global_packages.insert(package);
        }

        // 2. Data documents — inline mapping first, then files. Both are
        //    normalized to JSON (serde_yaml parses JSON too, so a `.json` or
        //    `.yaml` data file both work) and merged into the `data` root.
        if let Some(data) = map.get(serde_yaml::Value::String("data".into())) {
            if !data.is_null() {
                merge_data(&mut engine, "data", data)?;
            }
        }
        for path in read_string_seq(map, "data_files")? {
            let text = std::fs::read_to_string(&path).map_err(|source| BuildError::DataFile {
                path: path.clone(),
                source,
            })?;
            let parsed: serde_yaml::Value =
                serde_yaml::from_str(&text).map_err(|e| BuildError::DataParse {
                    name: path.clone(),
                    cause: e.to_string(),
                })?;
            merge_data(&mut engine, &path, &parsed)?;
        }

        Ok(Self {
            dialect: PdpDialect::Opa,
            on_error,
            decision_field,
            base_engine: engine,
            global_packages,
            inline_cache: RwLock::new(HashMap::new()),
            max_cache_entries: read_usize(map, "max_cache_entries")?
                .unwrap_or(DEFAULT_MAX_CACHE_ENTRIES),
        })
    }

    /// Override the resolver's dialect. Lets an operator register an OPA engine
    /// under a custom name so two OPA resolvers can coexist on one router.
    pub fn with_dialect(mut self, dialect: PdpDialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Override the inline-module cache cap (default
    /// [`DEFAULT_MAX_CACHE_ENTRIES`]). Equivalent to the `max_cache_entries`
    /// config key, for hosts constructing a resolver in Rust.
    pub fn with_max_cache_entries(mut self, max_cache_entries: usize) -> Self {
        self.max_cache_entries = max_cache_entries;
        self
    }

    /// Get an engine ready to evaluate this step: the base engine when the step
    /// carries no inline module, or a cached base+module engine otherwise. The
    /// returned engine is a fresh clone the caller mutates (set input, eval)
    /// without touching the shared base or cache. Cloning is cheap — regorus
    /// (`arc`) `Arc`-shares the compiled policy and data.
    fn engine_for(&self, module: Option<&str>) -> Result<Engine, EngineError> {
        let Some(src) = module else {
            return Ok(self.base_engine.clone());
        };

        // Fast path: this inline module was already prepared.
        if let Some(engine) = self
            .inline_cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(src)
        {
            return Ok(engine.clone());
        }

        // Prepare base + inline module. A parse failure here is a compile error
        // (always denies), not a runtime condition.
        //
        // A cold-start race can have two threads prepare the same module at
        // once. The second insert overwrites an equivalent engine, so the only
        // cost is a duplicated compile on first hit. That is deliberate:
        // holding the write lock across `add_policy` would serialize all
        // inline-module preparation. The cap check below is race-safe because
        // the length check and the insert share one write-lock acquisition, and
        // the `contains_key` guard keeps a same-key racer from being rejected
        // once the cache is full.
        let mut engine = self.base_engine.clone();
        let package = engine
            .add_policy(INLINE_MODULE_NAME.to_string(), src.to_string())
            .map_err(|e| EngineError::Compile(e.to_string()))?;

        // Reject an inline module that lands in a global module's package — it
        // would merge into (and could override) operator policy. Fail-closed:
        // inline modules may add new packages, never redefine a global one.
        if self.global_packages.contains(&package) {
            return Err(EngineError::PackageCollision(package));
        }

        // Insert under the cap — reject past it, never evict (workspace cache
        // convention).
        let mut cache = self.inline_cache.write().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= self.max_cache_entries && !cache.contains_key(src) {
            tracing::warn!(
                cap = self.max_cache_entries,
                "OPA inline-module cache full; rejecting new module. Existing entries are not \
                 evicted. Raise `max_cache_entries` in the OPA PDP config block if the policy \
                 legitimately needs more distinct inline modules."
            );
            return Err(EngineError::CacheFull {
                cap: self.max_cache_entries,
            });
        }
        cache.insert(src.to_string(), engine.clone());
        Ok(engine)
    }

    /// Apply `on_error` to a degenerate RUNTIME outcome (an eval error or a
    /// value carrying no decision). Allow logs at `error!` so a misused
    /// fail-open flag is never silent in production. (Compile errors, package
    /// collisions, and cache-full rejections do NOT come through here — they
    /// always deny via `compile_error_decision`.)
    fn on_error_decision(&self, cause: String) -> PdpDecision {
        match self.on_error {
            OnError::Allow => {
                tracing::error!(
                    cause = %cause,
                    "OPA runtime error; on_error=allow → allowing through. \
                     This is fail-open behavior; verify it is intentional."
                );
                PdpDecision {
                    decision: Decision::Allow,
                    diagnostics: vec![cause],
                }
            },
            OnError::Deny => PdpDecision {
                decision: Decision::Deny {
                    reason: Some(cause.clone()),
                    rule_source: "opa".to_string(),
                },
                diagnostics: vec![cause],
            },
        }
    }

    /// Always deny, regardless of `on_error`, for a non-negotiable failure: a
    /// Rego compile error (author bug), an inline/global package collision
    /// (trust-boundary violation), or a cache-full rejection (resource limit).
    /// None of these is a policy outcome that may fail open.
    fn compile_error_decision(&self, cause: String) -> PdpDecision {
        tracing::error!(
            cause = %cause,
            "OPA fail-closed condition — denying the request regardless of on_error mode."
        );
        PdpDecision {
            decision: Decision::Deny {
                reason: Some(cause.clone()),
                rule_source: "opa".to_string(),
            },
            diagnostics: vec![cause],
        }
    }
}

/// Internal — failure shapes from preparing a per-step engine. All three
/// always deny regardless of `on_error`: a compile error is an author bug, a
/// package collision is a trust-boundary violation, and a cache-full condition
/// is a resource limit — none is a legitimate policy outcome that should be
/// allowed to fail open.
enum EngineError {
    /// A Rego parse/compile error in an inline module.
    Compile(String),
    /// The inline module's package collides with a global-module package.
    PackageCollision(String),
    /// The inline-module cache hit its cap.
    CacheFull { cap: usize },
}

/// Outcome of the blocking evaluation task. Held as an owned, `Send` value so
/// it can cross the `spawn_blocking` boundary; `on_error` is applied by the
/// caller (which needs `&self` for logging).
enum EvalOutcome {
    /// A terminal decision the contract produced directly.
    Decision(PdpDecision),
    /// A degenerate runtime outcome (eval error, non-decision value) whose
    /// disposition depends on `on_error`.
    OnError(String),
}

#[async_trait]
impl PdpResolver for OpaResolver {
    fn dialect(&self) -> PdpDialect {
        self.dialect.clone()
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        // 1. Required `query` and optional inline `module` from the step args.
        //    A missing `query` is an author/config bug — hard error.
        let args = call.args.as_mapping();
        let query = args
            .and_then(|m| m.get(serde_yaml::Value::String("query".into())))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PdpError::Dispatch("opa: step requires a string `query` argument".to_string())
            })?;
        let module = args
            .and_then(|m| m.get(serde_yaml::Value::String("module".into())))
            .and_then(|v| v.as_str());

        // 2. Prepare the engine. A compile error, a package collision, and a
        //    cache-full rejection all always deny — none may fail open.
        let engine = match self.engine_for(module) {
            Ok(engine) => engine,
            Err(EngineError::Compile(cause)) => {
                return Ok(self.compile_error_decision(format!("OPA inline module: {cause}")));
            },
            Err(EngineError::PackageCollision(package)) => {
                return Ok(self.compile_error_decision(format!(
                    "OPA inline module package `{package}` collides with a global-module \
                     package; inline modules may not override global policy"
                )));
            },
            Err(EngineError::CacheFull { cap }) => {
                return Ok(self.compile_error_decision(format!(
                    "OPA inline-module cache full (cap={cap}); refusing a new module"
                )));
            },
        };

        // 3. Map the bag into the Rego `input` document, then set input and
        //    evaluate on a blocking thread — Rego eval is synchronous and can
        //    be CPU-heavy, and must not monopolize an async worker.
        let input_json = bag_to_input(bag).to_string();
        let query = query.to_string();
        let decision_field = self.decision_field.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let mut engine = engine;
            if let Err(e) = engine.set_input_json(&input_json) {
                return EvalOutcome::OnError(format!("OPA failed to set input: {e}"));
            }
            match engine.eval_rule(query) {
                Ok(value) => match map_query_result(&value, &decision_field) {
                    Mapped::Decision(decision) => EvalOutcome::Decision(decision),
                    Mapped::Degenerate(cause) => EvalOutcome::OnError(cause),
                },
                Err(e) => EvalOutcome::OnError(format!("OPA eval error: {e}")),
            }
        })
        .await;

        // 4. Apply on_error to genuine degenerate outcomes (eval error,
        //    non-decision value). A task panic/abort is an abnormal
        //    termination, not a policy outcome, so it always denies regardless
        //    of on_error — the same fail-closed treatment as compile errors.
        match outcome {
            Ok(EvalOutcome::Decision(decision)) => Ok(decision),
            Ok(EvalOutcome::OnError(cause)) => Ok(self.on_error_decision(cause)),
            Err(join_err) => Ok(
                self.compile_error_decision(format!("OPA evaluation task panicked: {join_err}"))
            ),
        }
    }
}

/// Normalize a YAML/JSON data document to JSON and merge it into the engine's
/// `data` root. `name` labels the source (`"data"` or a file path) in errors.
fn merge_data(
    engine: &mut Engine,
    name: &str,
    value: &serde_yaml::Value,
) -> Result<(), BuildError> {
    let to_err = |cause: String| BuildError::DataParse {
        name: name.to_string(),
        cause,
    };
    let json = serde_json::to_string(value).map_err(|e| to_err(e.to_string()))?;
    engine
        .add_data_json(&json)
        .map_err(|e| to_err(e.to_string()))?;
    Ok(())
}

/// Read an optional string field from a YAML mapping. A key that is absent (or
/// explicitly null) yields `None`; a key present with a non-string value is a
/// config error rather than a silent default, matching the strictness applied
/// to unknown keys and non-sequence `modules`.
fn read_string(map: &serde_yaml::Mapping, key: &str) -> Result<Option<String>, BuildError> {
    match map.get(serde_yaml::Value::String(key.to_string())) {
        None => Ok(None),
        Some(serde_yaml::Value::Null) => Ok(None),
        Some(value) => match value.as_str() {
            Some(s) => Ok(Some(s.to_string())),
            None => Err(BuildError::ConfigShape(format!("`{key}` must be a string"))),
        },
    }
}

/// Read an optional non-negative integer field. A key that is absent (or
/// explicitly null) yields `None`; a present value that is not a non-negative
/// integer is a config error rather than a silent default, matching the
/// strictness applied to the string fields.
fn read_usize(map: &serde_yaml::Mapping, key: &str) -> Result<Option<usize>, BuildError> {
    match map.get(serde_yaml::Value::String(key.to_string())) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| {
                BuildError::ConfigShape(format!("`{key}` must be a non-negative integer"))
            }),
    }
}

/// Read an optional sequence-of-strings field. A missing key yields an empty
/// vec; a present-but-non-sequence value, or a non-string element, is a config
/// error.
fn read_string_seq(map: &serde_yaml::Mapping, key: &str) -> Result<Vec<String>, BuildError> {
    let Some(value) = map.get(serde_yaml::Value::String(key.to_string())) else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let seq = value
        .as_sequence()
        .ok_or_else(|| BuildError::ConfigShape(format!("`{key}` must be a sequence of strings")))?;
    seq.iter()
        .map(|item| {
            item.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| BuildError::ConfigShape(format!("`{key}` entries must be strings")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> Result<OpaResolver, BuildError> {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        OpaResolver::from_config(&value)
    }

    #[test]
    fn builds_from_inline_module_and_data() {
        let r = cfg(r#"
kind: opa
on_error: deny
modules:
  - |
    package authz
    default allow := false
    allow if input.subject.id == "alice"
data:
  roles:
    alice: [reader]
"#)
        .expect("should build");
        assert_eq!(r.on_error, OnError::Deny);
        assert_eq!(r.decision_field, "allow");
    }

    #[test]
    fn on_error_allow_parses() {
        let r = cfg("kind: opa\non_error: allow\n").unwrap();
        assert_eq!(r.on_error, OnError::Allow);
    }

    #[test]
    fn on_error_bad_value_rejected() {
        let err = cfg("kind: opa\non_error: maybe\n").unwrap_err();
        assert!(matches!(err, BuildError::ConfigShape(m) if m.contains("on_error")));
    }

    #[test]
    fn decision_field_override_read() {
        let r = cfg("kind: opa\ndecision_field: permit\nmodules:\n  - \"package p\"\n").unwrap();
        assert_eq!(r.decision_field, "permit");
    }

    #[test]
    fn max_cache_entries_read_from_config() {
        let r = cfg("kind: opa\nmax_cache_entries: 7\n").unwrap();
        assert_eq!(r.max_cache_entries, 7);
    }

    #[test]
    fn max_cache_entries_defaults_when_absent() {
        let r = cfg("kind: opa\n").unwrap();
        assert_eq!(r.max_cache_entries, DEFAULT_MAX_CACHE_ENTRIES);
    }

    #[test]
    fn non_integer_max_cache_entries_is_rejected() {
        let err = cfg("kind: opa\nmax_cache_entries: many\n").unwrap_err();
        assert!(matches!(err, BuildError::ConfigShape(m) if m.contains("max_cache_entries")));
    }

    #[test]
    fn negative_max_cache_entries_is_rejected() {
        let err = cfg("kind: opa\nmax_cache_entries: -1\n").unwrap_err();
        assert!(matches!(err, BuildError::ConfigShape(m) if m.contains("max_cache_entries")));
    }

    #[test]
    fn unknown_key_rejected_naming_the_key() {
        let err = cfg("kind: opa\non_errr: allow\n").unwrap_err();
        match err {
            BuildError::ConfigShape(m) => assert!(m.contains("on_errr"), "got {m}"),
            other => panic!("expected ConfigShape, got {other:?}"),
        }
    }

    #[test]
    fn rego_parse_error_surfaces_at_build() {
        let err = cfg("kind: opa\nmodules:\n  - \"package x\\nallow if {\"\n").unwrap_err();
        assert!(matches!(err, BuildError::ModuleParse { .. }), "got {err:?}");
    }

    #[test]
    fn missing_module_file_names_the_path() {
        let err = cfg("kind: opa\nmodule_files:\n  - /no/such/authz.rego\n").unwrap_err();
        match err {
            BuildError::ModuleFile { path, .. } => assert_eq!(path, "/no/such/authz.rego"),
            other => panic!("expected ModuleFile, got {other:?}"),
        }
    }

    #[test]
    fn config_must_be_a_mapping() {
        let value: serde_yaml::Value = serde_yaml::from_str("- just\n- a\n- list\n").unwrap();
        assert!(matches!(
            OpaResolver::from_config(&value),
            Err(BuildError::ConfigShape(_))
        ));
    }

    #[test]
    fn modules_must_be_a_sequence() {
        let err = cfg("kind: opa\nmodules: not-a-list\n").unwrap_err();
        assert!(matches!(err, BuildError::ConfigShape(m) if m.contains("modules")));
    }

    #[test]
    fn non_string_on_error_is_rejected_not_silently_defaulted() {
        // A non-string `on_error` (here a list) must fail loudly at load rather
        // than silently falling back to the deny default.
        let err = cfg("kind: opa\non_error: [deny]\n").unwrap_err();
        assert!(matches!(err, BuildError::ConfigShape(m) if m.contains("on_error")));
    }

    #[test]
    fn non_string_decision_field_is_rejected() {
        let err =
            cfg("kind: opa\ndecision_field: {a: 1}\nmodules:\n  - \"package p\"\n").unwrap_err();
        assert!(matches!(err, BuildError::ConfigShape(m) if m.contains("decision_field")));
    }

    /// A distinct temp file path per test, so parallel tests never collide.
    fn temp_path(name: &str, ext: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cpex_opa_{}_{}.{ext}", std::process::id(), name))
    }

    #[test]
    fn module_files_load_and_evaluate() {
        let path = temp_path("modfile", "rego");
        std::fs::write(
            &path,
            "package authz\ndefault allow := false\nallow if input.subject.id == \"alice\"\n",
        )
        .unwrap();
        let yaml = format!("kind: opa\nmodule_files:\n  - {}\n", path.display());
        let r = cfg(&yaml).expect("module_files should load");
        // Prove the loaded rule actually evaluates.
        let mut engine = r.base_engine.clone();
        engine
            .set_input_json(r#"{"subject":{"id":"alice"}}"#)
            .unwrap();
        assert_eq!(
            engine
                .eval_rule("data.authz.allow".to_string())
                .unwrap()
                .as_bool()
                .copied()
                .ok(),
            Some(true)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn data_files_load_and_are_readable() {
        let path = temp_path("datafile", "json");
        std::fs::write(&path, r#"{"roles":{"alice":["reader"]}}"#).unwrap();
        let yaml = format!(
            "kind: opa\nmodules:\n  - |\n    package authz\n    default allow := false\n    allow if \"reader\" in data.roles[input.subject.id]\ndata_files:\n  - {}\n",
            path.display()
        );
        let r = cfg(&yaml).expect("data_files should load");
        let mut engine = r.base_engine.clone();
        engine
            .set_input_json(r#"{"subject":{"id":"alice"}}"#)
            .unwrap();
        assert_eq!(
            engine
                .eval_rule("data.authz.allow".to_string())
                .unwrap()
                .as_bool()
                .copied()
                .ok(),
            Some(true)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_data_file_names_the_path() {
        let err = cfg("kind: opa\ndata_files:\n  - /no/such/roles.json\n").unwrap_err();
        match err {
            BuildError::DataFile { path, .. } => assert_eq!(path, "/no/such/roles.json"),
            other => panic!("expected DataFile, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod eval_tests {
    use super::*;
    use std::sync::Arc;

    /// Build a resolver from a set of inline global modules.
    fn resolver(modules: &[&str], on_error: OnError) -> OpaResolver {
        let mut map = serde_yaml::Mapping::new();
        map.insert(sv("kind"), sv("opa"));
        if on_error == OnError::Allow {
            map.insert(sv("on_error"), sv("allow"));
        }
        let mods = modules.iter().map(|m| sv(m)).collect();
        map.insert(sv("modules"), serde_yaml::Value::Sequence(mods));
        OpaResolver::from_config(&serde_yaml::Value::Mapping(map)).unwrap()
    }

    fn sv(s: &str) -> serde_yaml::Value {
        serde_yaml::Value::String(s.to_string())
    }

    /// Build a resolver from raw config YAML, for tests exercising config keys
    /// the `resolver` helper does not set.
    fn resolver_from_yaml(yaml: &str) -> OpaResolver {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        OpaResolver::from_config(&value).unwrap()
    }

    /// Build an `opa:` step call with a query and optional inline module.
    fn call(query: &str, module: Option<&str>) -> PdpCall {
        let mut m = serde_yaml::Mapping::new();
        m.insert(sv("query"), sv(query));
        if let Some(src) = module {
            m.insert(sv("module"), sv(src));
        }
        PdpCall {
            dialect: PdpDialect::Opa,
            args: serde_yaml::Value::Mapping(m),
        }
    }

    fn bag(subject_id: &str) -> AttributeBag {
        let mut b = AttributeBag::new();
        b.set("subject.id", subject_id);
        b
    }

    const ALLOW_WITH_DEFAULT: &str = r#"package authz
default allow := false
allow if input.subject.id == "alice"
"#;

    const ALLOW_NO_DEFAULT: &str = r#"package authz
allow if input.subject.id == "alice"
"#;

    const DENY_SET: &str = r#"package authz
deny contains msg if {
    input.subject.id != "alice"
    msg := "subject not allowed"
}
"#;

    const DECISION_OBJECT: &str = r#"package authz
result := {"allow": input.subject.id == "alice"}
"#;

    const STRING_RESULT: &str = r#"package authz
msg := "not a decision"
"#;

    #[tokio::test]
    async fn allow_when_policy_grants() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny);
        let out = r
            .evaluate(&call("data.authz.allow", None), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(out.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn deny_when_policy_returns_false() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny);
        let out = r
            .evaluate(&call("data.authz.allow", None), &bag("eve"))
            .await
            .unwrap();
        assert!(matches!(out.decision, Decision::Deny { .. }));
    }

    /// Undefined (non-match with no `default`) is a clean deny even under
    /// on_error: allow — it must never fail open.
    #[tokio::test]
    async fn undefined_denies_even_with_on_error_allow() {
        let r = resolver(&[ALLOW_NO_DEFAULT], OnError::Allow);
        let out = r
            .evaluate(&call("data.authz.allow", None), &bag("eve"))
            .await
            .unwrap();
        match out.decision {
            Decision::Deny { reason, .. } => {
                assert!(reason.unwrap_or_default().contains("undefined"));
            },
            other => panic!("undefined must deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_set_empty_allows_nonempty_denies() {
        let r = resolver(&[DENY_SET], OnError::Deny);
        // Passing subject → empty deny set → allow.
        let allow = r
            .evaluate(&call("data.authz.deny", None), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(allow.decision, Decision::Allow);
        // Violating subject → non-empty deny set → deny with the message.
        let deny = r
            .evaluate(&call("data.authz.deny", None), &bag("eve"))
            .await
            .unwrap();
        assert!(matches!(deny.decision, Decision::Deny { .. }));
        assert!(deny.diagnostics.iter().any(|d| d == "subject not allowed"));
    }

    #[tokio::test]
    async fn decision_object_allow_and_deny() {
        let r = resolver(&[DECISION_OBJECT], OnError::Deny);
        let allow = r
            .evaluate(&call("data.authz.result", None), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(allow.decision, Decision::Allow);
        let deny = r
            .evaluate(&call("data.authz.result", None), &bag("eve"))
            .await
            .unwrap();
        assert!(matches!(deny.decision, Decision::Deny { .. }));
    }

    /// A value that carries no decision (a bare string) is degenerate → routes
    /// through on_error: deny by default, allow when configured.
    #[tokio::test]
    async fn non_decision_value_routes_through_on_error() {
        let deny_r = resolver(&[STRING_RESULT], OnError::Deny);
        let deny = deny_r
            .evaluate(&call("data.authz.msg", None), &bag("alice"))
            .await
            .unwrap();
        assert!(matches!(deny.decision, Decision::Deny { .. }));

        let allow_r = resolver(&[STRING_RESULT], OnError::Allow);
        let allow = allow_r
            .evaluate(&call("data.authz.msg", None), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(allow.decision, Decision::Allow);
    }

    /// An inline module with a Rego syntax error always denies, even under
    /// on_error: allow — malformed policy never flips to allow.
    #[tokio::test]
    async fn inline_compile_error_always_denies() {
        let r = resolver(&[], OnError::Allow);
        let out = r
            .evaluate(
                &call("data.x.allow", Some("package x\nallow if {")),
                &bag("alice"),
            )
            .await
            .unwrap();
        match out.decision {
            Decision::Deny { reason, .. } => {
                assert!(reason.unwrap_or_default().contains("inline module"));
            },
            other => panic!("compile error must deny, got {other:?}"),
        }
    }

    /// An inline module whose package collides with a global-module package is
    /// rejected fail-closed — it must not be able to merge into (and override)
    /// operator policy, even under on_error: allow.
    #[tokio::test]
    async fn inline_module_cannot_override_global_package() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Allow);
        // A hostile inline module tries to force allow in the operator's `authz`
        // package. It shares the package, so it is rejected → deny.
        let inline = "package authz\nallow if true\n";
        let out = r
            .evaluate(&call("data.authz.allow", Some(inline)), &bag("eve"))
            .await
            .unwrap();
        match out.decision {
            Decision::Deny { reason, .. } => {
                assert!(reason.unwrap_or_default().contains("collides"));
            },
            other => panic!("package collision must deny, got {other:?}"),
        }
    }

    /// An inline module in a fresh package (no global collision) is accepted and
    /// evaluates — inline modules remain a usable feature for additive policy.
    #[tokio::test]
    async fn inline_module_in_new_package_is_allowed() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny);
        let inline = "package extra\nallow if input.subject.id == \"alice\"\n";
        let out = r
            .evaluate(&call("data.extra.allow", Some(inline)), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(out.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn missing_query_is_dispatch_error() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny);
        let call = PdpCall {
            dialect: PdpDialect::Opa,
            args: serde_yaml::Value::Null,
        };
        let err = r.evaluate(&call, &bag("alice")).await.unwrap_err();
        assert!(matches!(err, PdpError::Dispatch(_)));
    }

    /// At the inline-module cache cap, a new distinct inline module is rejected
    /// and routed through on_error; an already-cached module still evaluates.
    #[tokio::test]
    async fn inline_cache_cap_rejects_new_modules() {
        let r = resolver(&[], OnError::Deny).with_max_cache_entries(1);
        let m1 = "package a\nallow if input.subject.id == \"alice\"\n";
        let m2 = "package b\nallow if input.subject.id == \"alice\"\n";

        // First inline module fills the cache and evaluates.
        let first = r
            .evaluate(&call("data.a.allow", Some(m1)), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(first.decision, Decision::Allow);

        // Second distinct module → cap rejection → on_error deny.
        let second = r
            .evaluate(&call("data.b.allow", Some(m2)), &bag("alice"))
            .await
            .unwrap();
        assert!(matches!(second.decision, Decision::Deny { .. }));
        assert!(second.diagnostics.iter().any(|d| d.contains("cache full")));

        // Cached module still works.
        let again = r
            .evaluate(&call("data.a.allow", Some(m1)), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(again.decision, Decision::Allow);
    }

    /// The `max_cache_entries` config key must reach the resolver, not just the
    /// Rust builder: an operator hitting the cap through unified config has no
    /// other lever.
    #[tokio::test]
    async fn config_max_cache_entries_reaches_the_resolver() {
        let r = resolver_from_yaml("kind: opa\nmax_cache_entries: 1\n");
        let m1 = "package a\nallow if input.subject.id == \"alice\"\n";
        let m2 = "package b\nallow if input.subject.id == \"alice\"\n";

        let first = r
            .evaluate(&call("data.a.allow", Some(m1)), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(first.decision, Decision::Allow);

        let second = r
            .evaluate(&call("data.b.allow", Some(m2)), &bag("alice"))
            .await
            .unwrap();
        assert!(matches!(second.decision, Decision::Deny { .. }));
        assert!(second.diagnostics.iter().any(|d| d.contains("cache full")));
    }

    /// A cap of 0 is a lockdown stance, not a footgun: inline modules are
    /// refused (and deny) while global-module steps keep evaluating, because a
    /// step without an inline module never touches the cache.
    #[tokio::test]
    async fn zero_max_cache_entries_disables_inline_modules_only() {
        const YAML: &str = r#"kind: opa
max_cache_entries: 0
modules:
  - |
    package authz
    default allow := false
    allow if input.subject.id == "alice"
"#;
        let r = resolver_from_yaml(YAML);

        let global = r
            .evaluate(&call("data.authz.allow", None), &bag("alice"))
            .await
            .unwrap();
        assert_eq!(global.decision, Decision::Allow);

        let inline = "package extra\nallow := true\n";
        let out = r
            .evaluate(&call("data.extra.allow", Some(inline)), &bag("alice"))
            .await
            .unwrap();
        assert!(
            matches!(out.decision, Decision::Deny { .. }),
            "an inline module must be refused at a cap of 0",
        );
    }

    /// A cache-full rejection is a resource limit, not a policy outcome, so it
    /// denies even under on_error: allow — it must not fail open.
    #[tokio::test]
    async fn inline_cache_cap_denies_even_under_on_error_allow() {
        let r = resolver(&[], OnError::Allow).with_max_cache_entries(1);
        let m1 = "package a\nallow if input.subject.id == \"alice\"\n";
        let m2 = "package b\nallow if input.subject.id == \"alice\"\n";
        let _ = r
            .evaluate(&call("data.a.allow", Some(m1)), &bag("alice"))
            .await
            .unwrap();
        let out = r
            .evaluate(&call("data.b.allow", Some(m2)), &bag("alice"))
            .await
            .unwrap();
        assert!(
            matches!(out.decision, Decision::Deny { .. }),
            "cache-full must deny even with on_error: allow",
        );
    }

    /// Reusing one resolver across requests must not serve a prior request's
    /// decision. Pins the regorus invariant the clone-per-request model rests
    /// on: cloning an engine and evaluating both clear the interpreter's
    /// input-derived memo state.
    #[tokio::test]
    async fn sequential_reuse_does_not_leak_prior_input() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny);
        for (subject, expected_allow) in [("alice", true), ("eve", false), ("alice", true)] {
            let out = r
                .evaluate(&call("data.authz.allow", None), &bag(subject))
                .await
                .unwrap();
            if expected_allow {
                assert_eq!(out.decision, Decision::Allow, "{subject} must be allowed");
            } else {
                assert!(
                    matches!(out.decision, Decision::Deny { .. }),
                    "{subject} must be denied, got {:?}",
                    out.decision,
                );
            }
        }
    }

    /// Many threads sharing one `Arc<OpaResolver>` evaluate concurrently and
    /// each gets the correct per-request decision (exercises clone-per-request
    /// under the `arc` feature). Together with
    /// `sequential_reuse_does_not_leak_prior_input`, guards against a regorus
    /// change that starts retaining input-derived state across evaluations.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_evaluation_is_correct() {
        let r = Arc::new(resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny));
        let tasks: Vec<_> = (0..64)
            .map(|i| {
                let r = Arc::clone(&r);
                tokio::spawn(async move {
                    let id = if i % 2 == 0 { "alice" } else { "eve" };
                    let out = r
                        .evaluate(&call("data.authz.allow", None), &bag(id))
                        .await
                        .unwrap();
                    (id, out.decision)
                })
            })
            .collect();
        for t in tasks {
            let (id, decision) = t.await.unwrap();
            if id == "alice" {
                assert_eq!(decision, Decision::Allow);
            } else {
                assert!(matches!(decision, Decision::Deny { .. }));
            }
        }
    }

    #[test]
    fn with_dialect_override_is_observable() {
        let r = resolver(&[ALLOW_WITH_DEFAULT], OnError::Deny)
            .with_dialect(PdpDialect::Custom("opa-strict".into()));
        assert_eq!(r.dialect(), PdpDialect::Custom("opa-strict".into()));
    }

    /// Security gate: the `http.send` builtin is excluded from the pinned
    /// regorus feature set, so an inline policy attempting network egress must
    /// not succeed — it fails to compile/evaluate and denies. Guards against a
    /// regorus upgrade or feature-set change silently re-enabling egress.
    #[tokio::test]
    async fn disabled_http_builtin_cannot_allow() {
        let r = resolver(&[], OnError::Deny);
        let inline = "package net\nallow if http.send({\"method\": \"get\", \"url\": \"http://example.com\"})\n";
        let out = r
            .evaluate(&call("data.net.allow", Some(inline)), &bag("alice"))
            .await
            .unwrap();
        assert!(
            matches!(out.decision, Decision::Deny { .. }),
            "http.send must be unavailable and deny, not allow",
        );
    }
}
