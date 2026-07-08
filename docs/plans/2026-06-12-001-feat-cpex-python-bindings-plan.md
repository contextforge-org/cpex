---
title: "feat: CPEX Python Bindings (PyO3, Rust-backed cpex package)"
type: feat
status: active
date: 2026-06-12
origin: docs/dev/issue19_requirements.md
deepened: 2026-06-12
---

# feat: CPEX Python Bindings (PyO3, Rust-backed cpex package)

## Summary

Build a new, standalone, Rust-backed Python package at `bindings/python/` that wraps
`cpex_core::PluginManager` via PyO3, exposing the Rust API faithfully (single `PipelineResult`,
dict payloads, `await`-based lifecycle). It mirrors the patterns of the existing C-FFI crate
`crates/cpex-ffi/` — factory registration, payload downcast-and-serialize, panic/timeout
isolation — while swapping the MessagePack/C-ABI wire for direct PyObject↔`serde_json`
traversal and `block_on` for `future_into_py`. The legacy pure-Python package at `./cpex/` is
left untouched. v1 supports CMF hooks (`MessagePayload`) and a `GenericPayload` fallback for all
other hook names; typed identity/delegation payloads are deferred to v2.

---

## Problem Frame

CPEX's canonical implementation is the Rust `cpex-core` runtime, but Python users can only reach
it through the legacy pure-Python framework at `./cpex/`, which has diverged conventions
(Pydantic payloads, 2-tuple returns, `GlobalContext`, `violations_as_exceptions`). Non-Rust hosts
otherwise reach the runtime only via the Go-oriented C FFI (`crates/cpex-ffi/`). A prior attempt
(PR #67) failed by trying to match the legacy Python API and by calling Python's `json` module
from Rust. Issue #19 asks for a thin, faithful PyO3 layer over the Rust contracts so Python users
get the canonical runtime with `from cpex import PluginManager`.

A finding the origin requirements doc omits, surfaced during planning: a `PluginManager` cannot
instantiate any config-driven plugin until its **factories are registered**. `crates/cpex-ffi/src/apl.rs`
(`cpex_apl_install`) registers each `apl-*` `KIND` factory and calls `apl_cpex::register_apl(...)`
*before* loading config. The Python binding must replicate this or every `invoke_hook` returns an
empty allow with no plugins firing.

---

## Requirements

Traced to the origin doc's Hard Constraints (C1–C5), Anti-Patterns (#1–#10), Deliverables table,
and Required Tests.

- R1. (C1, #1) Expose the Rust `PluginManager` API faithfully; do **not** adapt to the legacy Python API.
- R2. (C2, #3, #8) No silent failures at the FFI boundary: config/conversion errors → `ValueError`,
  plugin execution failure → `RuntimeError`, timeout → `TimeoutError`; `PipelineResult.errors` is never discarded.
- R3. (C3, #4) Safety: all async blocks crossing FFI wrapped in `catch_unwind` (panic → `RuntimeError`);
  value traversal capped at 128 levels (overflow → `ValueError`); never expose pointers in repr/errors.
- R4. (C4, #7, #10) Standalone package: `./cpex/` unmodified; independently installable; no import-time exceptions.
- R5. (C5) Self-contained maturin build (`module-name = "cpex._lib"`, `python-source = "python"`, `requires-python >= 3.10`).
- R6. (#2) Conversion uses direct PyObject↔`serde_json` traversal — never Python's `json` module from Rust.
- R7. Deliver every file in the origin Deliverables table (Rust src, Python package, pyproject, tests, MIGRATION.md, README.md, workspace + Makefile wiring).
- R8. Deliver the required test suites: `test_conversions.py`, `test_manager.py`, `test_errors.py`, `test_result.py`.
- R9. Provide a migration guide (`MIGRATION.md`) mapping legacy `cpex` → new Rust-backed `cpex`.

**Origin acceptance examples:** AE1 — `python -c "from cpex import PluginManager"` succeeds (R4, R5).
AE2 — a `cmf.tool_pre_invoke` invoke against a denying config returns `continue_processing == False`
with a populated `violation` (R1, R2). AE3 — legacy root `pytest tests/` passes unchanged (R4).

---

## Scope Boundaries

- Not modifying `./cpex/` (legacy package) in any way — no `__init__.py` edits, no backend selection (#9, #10).
- No backend-selection / dual-mode logic — this package is always Rust-backed (#9).
- Not re-exposing every Rust extension/PDP knob; only the `PluginManager` lifecycle + `invoke_hook` contract.

### Deferred to Follow-Up Work

- **Typed identity/delegation payloads** (`identity_resolve` → `IdentityPayload`, `token_delegate` →
  `DelegationPayload`): deferred to v2. Their secret token fields (`raw_token`, `bearer_token`) are
  `#[serde(skip)]`, so dict→serde construction silently drops the token (see Key Technical Decisions
  KD1). v1 routes these hooks through `GenericPayload`, preserving the raw dict. v2 will add typed
  constructors and a token-injection path (kwarg or `Extensions.raw_credentials`, mirroring
  `cpex-ffi`'s `cpex_invoke_resolved` at `crates/cpex-ffi/src/lib.rs:961`).
- **Cedarling-backed identity/PDP**: present only behind an optional `cedarling` Cargo feature (off by default), mirroring `cpex-ffi`.
- **`result.wait_background()` / explicit background-task handle**: v1 relies on `shutdown()` to drain
  fire-and-forget tasks (KD4). A per-call wait API can follow if needed.

---

## Context & Research

### Relevant Code and Patterns

- `crates/cpex-ffi/` — the production reference this plan mirrors. Key sites:
  - Factory registration + `register_apl`: `crates/cpex-ffi/src/apl.rs:56`
  - Shared tokio runtime w/ `CPEX_FFI_WORKER_THREADS` knob + rationale: `crates/cpex-ffi/src/lib.rs:117`
  - Payload downcast-and-serialize (`serialize_payload`): `crates/cpex-ffi/src/lib.rs:357`
  - Synthetic error record on payload-serialize failure: `crates/cpex-ffi/src/lib.rs:877`
  - `GenericPayload` + `impl_plugin_payload!`: `crates/cpex-ffi/src/lib.rs:1357` (struct is **local**, not exported from core)
  - Fixed wall-clock timeout constant `FFI_WALL_CLOCK_TIMEOUT`: `crates/cpex-ffi/src/lib.rs:115`
- `cpex-core` verified API (against source):
  - `PluginManager::default()` (wrap in `Arc`); `register_factory(&self, kind, Box<dyn PluginFactory>)` `crates/cpex-core/src/manager.rs:456`
  - `load_config_yaml(self: &Arc<Self>, yaml: &str) -> Result<(), Box<PluginError>>` `crates/cpex-core/src/manager.rs:556` (runs config visitors — required for APL; passes `Arc::clone(self)` to visitors at `:591`)
  - `parse_config(yaml) -> Result<CpexConfig, Box<PluginError>>` `crates/cpex-core/src/config.rs:567`
  - `async initialize(&self)` `:812`; `async shutdown(&self)` `:876` (drains `TaskTracker` at `:889`); `async invoke_by_name(&self, &str, Box<dyn PluginPayload>, Extensions, Option<PluginContextTable>) -> (PipelineResult, BackgroundTasks)` `:932`
  - `Extensions` derives `Default + Serialize + Deserialize`; data fields `#[serde(default, skip_serializing_if=...)]`, `WriteToken` fields `#[serde(skip)]` — partial dicts deserialize safely `crates/cpex-core/src/extensions/container.rs:48`
  - `impl_plugin_payload!` macro is exported from core `crates/cpex-core/src/hooks/payload.rs:118`
  - Fire-and-forget tasks spawn on the manager's `TaskTracker` `crates/cpex-core/src/executor.rs:980`; dropping `BackgroundTasks` (`executor.rs:175`) detaches handles but does not cancel
- Bundled APL plugin kinds (verified) usable in test fixtures:
  - `validator/pii-scan` (`crates/apl-pii-scanner/src/factory.rs:20`) — registers on `cmf.tool_pre_invoke`, emits `pii.detected` violation in `deny` mode (`crates/apl-pii-scanner/src/scanner.rs:197`)
  - `audit/logger` (`crates/apl-audit-logger/src/factory.rs:20`) — fire-and-forget
  - `identity/jwt` (`crates/apl-identity-jwt/src/factory.rs:42`), `delegator/oauth` (`crates/apl-delegator-oauth/src/factory.rs:41`)
- Legacy test conventions to mirror: `tests/pytest.ini`, `tests/unit/cpex/conftest.py` (autouse reset fixtures, no module-level `os.environ` mutation).

### Institutional Learnings

- PR #67 anti-patterns (origin doc §Anti-Patterns) are the governing "do not repeat" list; each is mapped to a requirement above.

### External References

- `pyo3-async-runtimes` latest is **0.28.0** (2026-02-04), requires `pyo3 ^0.28`. Pin both to `0.28` with the `tokio-runtime` feature.

---

## Key Technical Decisions

- **KD1 (resolves B1):** Defer typed identity/delegation to v2; route `identity_resolve` / `token_delegate`
  through `GenericPayload` in v1. Rationale: `raw_token`/`bearer_token` are `#[serde(skip)]`, so serde
  construction yields tokenless payloads — silent no-ops. `cpex-ffi` itself doesn't dispatch delegation and
  handles identity via a separate raw-creds entry point.
- **KD2 (resolves B3 / reconciles C2):** Unknown/legacy/custom hook names do **not** raise — they map to
  `GenericPayload`, faithful to `cpex_core` where `invoke_by_name` accepts any hook string and never emits
  `UnknownHook`. The origin's C2 "Unknown hook → ValueError" row is **explicitly retracted as unreachable**;
  the `ValueError` guarantee instead covers conversion failures (incl. a `GenericPayload` dict that fails
  `from_value`) and config errors. `test_errors.py` tests *conversion failure*, not "unknown hook".
- **KD3 (resolves B2):** `pyo3/extension-module` is an opt-in (non-default) feature enabled only by maturin.
  `build.rs` emits `-undefined dynamic_lookup` on macOS **only when `CARGO_FEATURE_EXTENSION_MODULE` is unset**
  (avoids double-flag under maturin). To keep the pure-Rust workspace build independent of libpython, the
  Makefile's `rust-build`/`rust-test` exclude this crate (`--workspace --exclude cpex-python`); it is built
  and tested via the `bindings-python-*` (maturin) targets. `cargo build -p cpex-python` remains the explicit
  verification path on a machine with Python present.
- **KD4 (resolves M1):** `invoke_hook` returns only `PipelineResult` and drops `BackgroundTasks`; fire-and-forget
  tasks keep running on the manager's `TaskTracker` and are guaranteed flushed by `await shutdown()`. The
  deterministic AE2 violation assertion uses the **sequential** `validator/pii-scan` plugin (no raciness);
  fire-and-forget behavior is asserted only after `shutdown()`. Documented in README/MIGRATION.
- **KD5 (resolves M2):** Define a crate-local `GenericPayload { value: serde_json::Value }` + `cpex_core::impl_plugin_payload!`
  (the macro is exported from core; the struct is not). House factory registration in a dedicated `builtins.rs`,
  not inlined in `#[new]`.
- **KD6 (resolves M3):** Pin `pyo3 = "0.28"`, `pyo3-async-runtimes = { version = "0.28", features = ["tokio-runtime"] }`.
  Verify the resolved `tokio` lower bound stays `>= 1.51` so the workspace lockfile (shared with `cpex-ffi`) does not regress.
- **KD7 (resolves M4):** Wall-clock timeout is **not optional** — a fixed constant mirroring `FFI_WALL_CLOCK_TIMEOUT`;
  `Elapsed` → `TimeoutError`.
- **KD8 (resolves M5):** Initialize the `pyo3-async-runtimes` tokio runtime with an explicit multi-thread builder
  honoring a `CPEX_PY_WORKER_THREADS` env var (mirroring `worker_threads_from_env` at `crates/cpex-ffi/src/lib.rs:148`).
  Do not claim it "reuses cpex-ffi's runtime" — it is a separate runtime; the shared-thread-budget *philosophy* is mirrored, the runtime instance is not.
- **KD9 (resolves M6):** In `error.rs`, document that `PluginError::Violation` is unreachable via `invoke_by_name`
  (denials return as `Ok(PipelineResult{ continue_processing:false, violation })`, never raised). Keep a defensive
  mapping but comment it as dead-on-this-path.
- **KD10 (resolves L2):** Test fixtures use bundled APL kinds (`validator/pii-scan` deny-mode for AE2; `audit/logger`
  for fire-and-forget) — **not** the Go-demo-only `builtin/cmf-tool-policy`.
- **KD11 (resolves L3):** The new package shares the import name `cpex` with the legacy package; enforce a hard rule
  that it is only ever installed in its own venv, and add a guard test asserting `cpex._lib` is importable so a
  polluted `sys.path` fails loudly rather than silently importing legacy `./cpex/`.

---

## Open Questions

### Resolved During Planning

- Identity/delegation v1 handling → deferred (KD1).
- Unknown-hook semantics vs C2 → GenericPayload fallback, C2 row retracted (KD2).
- Workspace/libpython build conflict → off-by-default feature + Makefile exclude (KD3).
- Which plugin backs the CMF smoke test → `validator/pii-scan` (KD10).
- pyo3 version → 0.28 (KD6).

### Deferred to Implementation

- Exact `pyo3-async-runtimes` 0.28 runtime-init call (`tokio::init` / builder hook) — confirm against the 0.28 API at implementation time.
- Final value of the wall-clock timeout constant (match `cpex-ffi`'s value unless tests need otherwise).
- Whether `_lib.pyi` can express the awaitable return types precisely or should omit (per #5, omit rather than guess).

---

## Output Structure

    bindings/python/
    ├── Cargo.toml              # crate cpex-python, cdylib, lib name _lib
    ├── build.rs                # macOS dynamic_lookup, gated on extension-module off
    ├── src/
    │   ├── lib.rs              # #[pymodule] _lib; runtime init (CPEX_PY_WORKER_THREADS)
    │   ├── manager.rs          # PyPluginManager: #[new], initialize/shutdown/invoke_hook
    │   ├── builtins.rs         # register_builtin_factories + register_apl (cedarling-gated)
    │   ├── conversions.rs      # pyobj<->json, resolve_payload, serialize_payload, GenericPayload
    │   ├── error.rs            # PluginError -> PyErr
    │   └── result.rs           # PyPipelineResult + pipeline_result_to_py
    ├── python/
    │   └── cpex/
    │       ├── __init__.py     # re-export PluginManager, PipelineResult from cpex._lib
    │       └── _lib.pyi        # type stubs
    ├── pyproject.toml          # maturin build config
    ├── tests/
    │   ├── conftest.py         # fixtures (manager, fixture-config path); no os.environ mutation
    │   ├── fixtures/
    │   │   └── pii_deny.yaml   # validator/pii-scan deny on cmf.tool_pre_invoke + audit/logger
    │   ├── test_conversions.py
    │   ├── test_manager.py
    │   ├── test_errors.py
    │   └── test_result.py
    ├── MIGRATION.md
    └── README.md

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
invoke_hook(hook_name, payload: dict, extensions=None, context_table=None)  ->  awaitable[PipelineResult]

  [GIL held]
    payload_value   = pyobj_to_json_value(payload, depth=0)      # R6, depth<=128 (R3)
    rust_payload    = resolve_payload(hook_name, payload_value)  # cmf.* -> MessagePayload; else GenericPayload (KD1,KD2)
    rust_extensions = from_value::<Extensions>(extensions or {})
    rust_context    = from_value::<Option<PluginContextTable>>(context_table)
    manager         = Arc::clone(&self.inner)                    # owned clone into future (lifetime; APL Weak upgrade)
  [GIL released]  future_into_py:
    timeout(FFI_WALL_CLOCK_TIMEOUT,                              # KD7 -> Elapsed => TimeoutError
      catch_unwind(AssertUnwindSafe(                             # R3 -> panic => RuntimeError
        manager.invoke_by_name(hook_name, rust_payload, rust_extensions, rust_context))))
      -> (pipeline_result, _bg_tasks)                            # bg dropped; flushed on shutdown() (KD4)
  [GIL re-acquired]
    pipeline_result_to_py(pipeline_result)                       # downcast modified_payload; synthetic error on failure (R2)
```

Construction (`#[new]`, sync): `PluginManager::default()` → `Arc` → `builtins::register_builtin_factories(&arc)`
(register each `apl-*::KIND` + `apl_cpex::register_apl(&arc, AplOptions::in_process() with cedar-direct pdp)`) →
`read_to_string(config_path)` (IO err → `ValueError`) → `parse_config` (parse err → `ValueError`) →
`arc.load_config_yaml(yaml)` (err → `ValueError`). Order matters: factories + `register_apl` must run on the
**same Arc** later passed to `load_config_yaml` so the APL visitor's `Weak<PluginManager>` upgrades during load.

---

## Implementation Units

- U1. **Workspace, crate scaffolding & build wiring**

**Goal:** Create the `cpex-python` crate skeleton, wire it into the workspace and build without breaking the pure-Rust build.

**Requirements:** R5, R7; KD3, KD6.

**Dependencies:** None.

**Files:**
- Create: `bindings/python/Cargo.toml` (`[package] name="cpex-python"`; `[lib] name="_lib"`, `crate-type=["cdylib"]`; deps `cpex-core` + the APL set [`apl-cpex`, `apl-pii-scanner`, `apl-audit-logger`, `apl-identity-jwt`, `apl-delegator-oauth`, `apl-pdp-cedar-direct`; `apl-cedarling` optional under `cedarling`]; `serde`/`serde_json`/`tokio`/`futures` via `{workspace=true}`; `pyo3="0.28"` with non-default `extension-module` feature; `pyo3-async-runtimes="0.28"` `["tokio-runtime"]`)
- Create: `bindings/python/build.rs` (macOS `-undefined dynamic_lookup`, gated on `CARGO_FEATURE_EXTENSION_MODULE` unset — KD3)
- Modify: `Cargo.toml` (root) — add `"bindings/python"` to `[workspace] members`
- Modify: `Makefile` — `rust-build`/`rust-test` use `--workspace --exclude cpex-python`; add `bindings-python-build`/`-build-release`/`-test` (maturin) targets matching existing emoji + `.PHONY` style

**Approach:** Crate compiles as an empty `#[pymodule]` first to validate the build matrix before logic lands.

**Patterns to follow:** `crates/cpex-ffi/Cargo.toml` (APL dep set, optional `cedarling`); existing `Makefile` Rust targets (`Makefile:444`).

**Test scenarios:** Test expectation: none — scaffolding/config. Verified by build, not unit tests.

**Verification:** `cargo build -p cpex-python` succeeds (macOS); `make rust-build` succeeds and does **not** attempt the python crate; `cargo metadata` shows resolved `tokio >= 1.51` (KD6).

---

- U2. **Error mapping (`error.rs`)**

**Goal:** Map `Box<PluginError>` and FFI-boundary failures to Python exceptions per C2.

**Requirements:** R2; KD9.

**Dependencies:** U1.

**Files:**
- Create: `bindings/python/src/error.rs`

**Approach:** `Config`/`UnknownHook` → `ValueError`; `Timeout` → `TimeoutError`; `Execution`/unexpected → `RuntimeError`.
Comment that `PluginError::Violation` is unreachable on the `invoke_by_name` path (KD9). Provide a single
`plugin_error_to_pyerr` helper reused across modules. Never include pointers/`{:p}` in messages (R3).

**Patterns to follow:** `crates/cpex-core/src/error.rs` variant shapes; `crates/cpex-ffi/src/lib.rs` RC mapping intent.

**Test scenarios:** (covered via U7 `test_errors.py`)
- Error path: each variant maps to the documented Python exception type (asserted end-to-end in U7).

**Verification:** Helper compiles and is referenced by manager/conversions; no pointer formatting present.

---

- U3. **Value conversion & payload dispatch (`conversions.rs`)**

**Goal:** Direct PyObject↔`serde_json` traversal, payload resolution, and modified-payload serialization — no Python `json`.

**Requirements:** R1, R2, R3, R6; KD1, KD2, KD5.

**Dependencies:** U2.

**Files:**
- Create: `bindings/python/src/conversions.rs`

**Approach:**
- `pyobj_to_json_value(py, obj, depth)`: `bool`/`int`/`float`/`str`/`None`/`PyList`/`PyDict` → `Value`; `depth > 128` → `ValueError` (R3); unknown type → `ValueError` naming the type.
- `json_value_to_pyobj(py, &Value)`: reverse, building `PyDict`/`PyList`.
- Define local `GenericPayload { value }` + `cpex_core::impl_plugin_payload!` (KD5).
- `resolve_payload(hook_name, value)`: `cmf.*` → `MessagePayload`; **else** `GenericPayload { value }` (KD1, KD2). `from_value` failure → descriptive `ValueError`.
- `serialize_payload(&dyn PluginPayload) -> Option<Value>`: `downcast_ref` ordered (MessagePayload, GenericPayload) → `to_value`; `None` signals "unknown type" so the caller records a synthetic error (R2, #8).
- `Extensions` and `PluginContextTable` via `from_value`/`to_value` (both serde types).

**Patterns to follow:** origin doc conversion sketches; `crates/cpex-ffi/src/lib.rs:357` downcast ordering; `crates/cpex-core/src/extensions/container.rs:48` serde attrs.

**Test scenarios:** (covered via U7 `test_conversions.py`)
- Happy path: round-trip flat dict, nested dict/list, mixed scalar types (bool/int/float/str/None).
- Edge case: empty dict, empty list, `None` value, dict with non-str... (str keys only — assert non-str key → `ValueError`).
- Edge case: nesting exactly 128 deep succeeds; 129 deep → `ValueError`.
- Error path: unconvertible Python object (e.g. a set or custom object) → `ValueError` naming the type.

**Verification:** Round-trip tests pass; depth guard triggers at 129.

---

- U4. **`PyPluginManager` + factory registration + async lifecycle (`manager.rs`, `builtins.rs`, `lib.rs`)**

**Goal:** Construct the manager with bundled factories, expose `initialize`/`shutdown`/`invoke_hook` as awaitables, with panic + timeout isolation.

**Requirements:** R1, R2, R3, R4; KD3, KD4, KD5, KD7, KD8.

**Dependencies:** U2, U3.

**Files:**
- Create: `bindings/python/src/manager.rs`
- Create: `bindings/python/src/builtins.rs`
- Create: `bindings/python/src/lib.rs`

**Approach:**
- `lib.rs`: `#[pymodule] fn _lib(...)` registering `PyPluginManager` + `PyPipelineResult`; initialize the `pyo3-async-runtimes` tokio runtime with a multi-thread builder honoring `CPEX_PY_WORKER_THREADS` (KD8). No work at import time beyond registration (R4, #7).
- `builtins.rs`: `register_builtin_factories(&Arc<PluginManager>)` = the `crates/cpex-ffi/src/apl.rs:56` sequence (`register_factory` per `apl-*::KIND` + `apl_cpex::register_apl(&arc, AplOptions::in_process()` with cedar-direct `pdp_factory`)). `apl-cedarling` wiring `#[cfg(feature="cedarling")]`.
- `manager.rs`: `PyPluginManager { inner: Arc<PluginManager> }`. `#[new] fn new(config_path)` sync per the design's construction sequence (factories on the **same Arc** later loaded — preserves APL `Weak` upgrade). `initialize`/`shutdown`/`invoke_hook` return `future_into_py` awaitables; each clones `Arc` into the future (lifetime + APL upgrade). `invoke_hook` follows the design sketch: convert under GIL → release → `timeout(catch_unwind(...))` → re-acquire GIL → `pipeline_result_to_py`. Drop `_bg_tasks` (KD4).

**Execution note:** Land an end-to-end "construct → initialize → invoke → shutdown" integration test early (U7) to exercise the GIL/runtime boundary before refining conversions.

**Patterns to follow:** `crates/cpex-ffi/src/apl.rs` (registration), `crates/cpex-ffi/src/lib.rs:117` (runtime/env knob), origin doc async pattern.

**Test scenarios:** (covered via U7 `test_manager.py` / `test_errors.py`)
- Happy path: construct from fixture config, `await initialize()`, `await invoke_hook("cmf.tool_pre_invoke", ...)`, `await shutdown()`.
- Integration: `validator/pii-scan` deny config → `continue_processing == False` with `violation` (AE2).
- Error path: missing config file → `ValueError`; malformed YAML → `ValueError`.
- Edge case: `invoke_hook` with a non-CMF hook name routes through GenericPayload and returns a result (no raise) (KD2).

**Verification:** AE1 (`from cpex import PluginManager`) and AE2 hold; no import-time exception; `CPEX_PY_WORKER_THREADS` respected.

---

- U5. **`PyPipelineResult` (`result.rs`)**

**Goal:** Expose `PipelineResult` fields read-only as Python types, surfacing errors faithfully.

**Requirements:** R1, R2, R3; KD9.

**Dependencies:** U3.

**Files:**
- Create: `bindings/python/src/result.rs`

**Approach:** `#[pyclass] PyPipelineResult` getters: `continue_processing: bool`, `modified_payload: Optional[dict]`,
`modified_extensions: Optional[dict]`, `violation: Optional[dict]`, `errors: list[dict]`, `metadata: Optional[dict]`,
`context_table: dict`. `pipeline_result_to_py` builds it; if `serialize_payload` returns `None` for a modified payload,
append a synthetic `{plugin_name:"<py>", code:"py_serialize_error", ...}` to `errors` (R2, #8;
mirrors `crates/cpex-ffi/src/lib.rs:877`). `__repr__` must not expose pointers (R3).

**Patterns to follow:** `crates/cpex-core/src/executor.rs` `PipelineResult` shape; `crates/cpex-ffi/src/lib.rs:877` synthetic-error pattern.

**Test scenarios:** (covered via U7 `test_result.py`)
- Happy path: all seven fields accessible with correct types after a real invoke.
- Integration: deny result exposes `violation` dict with `{reason, description, code, details}`; `continue_processing False`.
- Error path: a plugin run with `on_error: ignore` surfaces an entry in `errors` (not raised, not dropped).
- Edge case: `__repr__` contains no `0x`/pointer-like substrings.

**Verification:** `test_result.py` asserts field access, violation presence, and error surfacing.

---

- U6. **Python package surface (`__init__.py`, `_lib.pyi`, `pyproject.toml`)**

**Goal:** Importable `cpex` package re-exporting the native module, with stubs and maturin config.

**Requirements:** R4, R5, R7; #5.

**Dependencies:** U4, U5.

**Files:**
- Create: `bindings/python/python/cpex/__init__.py` (re-export `PluginManager`, `PipelineResult` from `cpex._lib`)
- Create: `bindings/python/python/cpex/_lib.pyi` (stubs matching Rust signatures; omit uncertain types rather than guess — #5)
- Create: `bindings/python/pyproject.toml` (maturin backend; `module-name="cpex._lib"`; `features=["pyo3/extension-module"]`; `python-source="python"`; `requires-python>=3.10`)

**Approach:** Minimal `__init__.py`; no import-time side effects (R4, #7).

**Patterns to follow:** origin doc C5 pyproject block.

**Test scenarios:**
- Happy path (covered in U7): `from cpex import PluginManager, PipelineResult` succeeds (AE1).

**Verification:** `maturin develop` installs; `python -c "from cpex import PluginManager"` works; `mypy bindings/python/python/cpex/` passes.

---

- U7. **Test fixtures + suite**

**Goal:** Implement the four required test modules + a bundled-APL fixture config and guard test.

**Requirements:** R8; KD4, KD10, KD11.

**Dependencies:** U4, U5, U6.

**Files:**
- Create: `bindings/python/tests/conftest.py` (manager fixture; fixture-config path; reset between tests; no module-level `os.environ` mutation — #6)
- Create: `bindings/python/tests/fixtures/pii_deny.yaml` (`validator/pii-scan` `mode: sequential`, deny on `cmf.tool_pre_invoke`; `audit/logger` fire-and-forget) — KD10
- Create: `bindings/python/tests/test_conversions.py`, `test_manager.py`, `test_errors.py`, `test_result.py`

**Approach:** `test_manager.py` includes the AE2 deny assertion via the **sequential** pii-scanner (deterministic, KD4) and a separate fire-and-forget audit assertion performed only after `await shutdown()`. Add a guard test asserting `cpex._lib` is importable / `cpex.__file__` resolves to the extension (KD11). `test_errors.py` tests conversion failure (KD2), missing config, malformed YAML, and **timeout** (KD7).

**Patterns to follow:** `tests/unit/cpex/conftest.py` fixture style; `tests/pytest.ini` config.

**Test scenarios:** (this unit *is* the tests; scenarios enumerated per U3/U4/U5 above plus:)
- Error path: `invoke_hook` exceeding the wall-clock timeout → `TimeoutError` (KD7) — use a fixture plugin/config that stalls, or a very low `CPEX_*` override if available.
- Integration: after `shutdown()`, the fire-and-forget `audit/logger` side effect is observed (KD4).
- Edge case: importing `cpex` resolves to the extension, not legacy `./cpex/` (KD11).

**Verification:** `cd bindings/python && pytest tests/` passes in an isolated venv.

---

- U8. **Migration guide & README**

**Goal:** Document the legacy→new mapping and quickstart, including the v1 scope caveats.

**Requirements:** R9, R7; KD1, KD4, KD11.

**Dependencies:** U6.

**Files:**
- Create: `bindings/python/MIGRATION.md` (the origin doc's legacy↔new mapping table: import path, `invoke_hook` args, hook names, tuple vs single result, dict vs Pydantic payloads, context handling, error surfacing)
- Create: `bindings/python/README.md` (install via `maturin develop`, quickstart, the shutdown-flush contract (KD4), the separate-venv rule (KD11), and the v1 identity/delegation-deferred note (KD1))

**Approach:** Prose only; no code changes.

**Test scenarios:** Test expectation: none — documentation.

**Verification:** Links resolve; mapping table matches the implemented API surface.

---

## System-Wide Impact

- **Interaction graph:** New crate consumes `cpex-core` + APL crates; fire-and-forget plugins run on the manager `TaskTracker`, drained by `shutdown()`. `invoke_hook`'s future holds an owned `Arc<PluginManager>` clone (lifetime + APL `Weak` upgrade).
- **Error propagation:** Halting denials → `PipelineResult.violation` (not raised); non-halting plugin errors → `PipelineResult.errors`; only config/conversion/timeout/panic raise.
- **State lifecycle risks:** Dropping `BackgroundTasks` is safe (detach, not cancel) but completion is only guaranteed across `shutdown()`; tests assert fire-and-forget effects post-shutdown.
- **API surface parity:** `invoke_hook` mirrors `invoke_by_name`; no legacy 2-tuple/`GlobalContext` surface (R1).
- **Build/CI impact:** Workspace gains a maturin crate; `make rust-build`/`rust-test` exclude it; pure-Rust CI stays libpython-independent (KD3). Lockfile shares `tokio` with `cpex-ffi` — must not regress below 1.51 (KD6).
- **Unchanged invariants:** `./cpex/` legacy package and its root `pytest tests/` are untouched and must still pass (R4, AE3).

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Linux `cargo build --workspace` tries to link libpython and fails | `extension-module` off by default + Makefile excludes the crate from pure-Rust targets; built via maturin (KD3) |
| `pyo3-async-runtimes` 0.28 runtime-init API differs from assumption | Deferred-to-implementation: confirm exact `tokio::init`/builder call against 0.28 at build time |
| Workspace `tokio` downgrade from pyo3-async-runtimes transitive bound | Verify resolved `tokio >= 1.51` via `cargo metadata` in U1 (KD6) |
| Fire-and-forget audit test flakiness | AE2 uses sequential pii-scanner; audit asserted only post-`shutdown()` (KD4) |
| Import-name collision with legacy `./cpex/` | Separate-venv hard rule + guard test asserting `cpex._lib` resolves (KD11) |
| Double `-undefined dynamic_lookup` under maturin | build.rs gates the flag on `CARGO_FEATURE_EXTENSION_MODULE` unset (KD3) |

---

## Documentation / Operational Notes

- README documents the `CPEX_PY_WORKER_THREADS` knob, the `shutdown()`-flush contract, and the isolated-venv requirement.
- MIGRATION.md is the primary onboarding artifact for legacy `cpex` users.

---

## Verification

1. `cargo build -p cpex-python` compiles (macOS dynamic_lookup via build.rs); `make rust-build` succeeds without touching the python crate.
2. `cd bindings/python && maturin develop` installs the extension into a venv.
3. `python -c "from cpex import PluginManager; print('ok')"` (AE1).
4. `cd bindings/python && pytest tests/` passes (R8) in an isolated venv.
5. Root `pytest tests/` (legacy `cpex`) passes unchanged — `./cpex/` untouched (R4, AE3).
6. `mypy bindings/python/python/cpex/` passes against the stubs.
7. AE2 spot-check: a `cmf.tool_pre_invoke` invoke against the `validator/pii-scan` deny fixture returns
   `continue_processing == False` with a populated `violation`; an `on_error: ignore` plugin error surfaces in `result.errors`.

---

## Sources & References

- **Origin document:** [docs/dev/issue19_requirements.md](docs/dev/issue19_requirements.md)
- Reference crate: `crates/cpex-ffi/` (esp. `src/apl.rs`, `src/lib.rs`)
- Core API: `crates/cpex-core/src/manager.rs`, `executor.rs`, `extensions/container.rs`, `config.rs`, `hooks/payload.rs`
- Bundled APL kinds: `crates/apl-pii-scanner/src/factory.rs`, `crates/apl-audit-logger/src/factory.rs`, `crates/apl-identity-jwt/src/factory.rs`, `crates/apl-delegator-oauth/src/factory.rs`
- External: `pyo3-async-runtimes` 0.28.0 (requires `pyo3 ^0.28`)
