---
title: "feat: Add python-isolated:// plugin adapter"
date: 2026-06-17
origin: docs/brainstorms/2026-06-15-python-plugin-compat-requirements.md
milestone: 0.2.0
issue: "#20"
status: ready
deepened: 2026-06-17
---

# feat: Add `python-isolated://` Plugin Adapter

**Origin:** `docs/brainstorms/2026-06-15-python-plugin-compat-requirements.md`  
**Milestone:** 0.2.0 · **Issue:** #20  
**Dependency:** Issue #19 (cpex-python bindings) — complete as of d158db5

---

## Summary

Add a new crate `crates/cpex-hosts-python` that lets the Rust `PluginManager` load and invoke Python plugin classes through a subprocess-isolated virtual environment. Plugin operators declare `kind: "python-isolated://module.ClassName"` in YAML; the Rust runtime creates and manages the venv, spawns the existing `cpex/framework/isolated/worker.py` process, and drives it via the JSON-lines stdin/stdout protocol already used by `IsolatedVenvPlugin` on the Python side.

No PyO3 dependency is introduced. The in-process `python://` adapter is deferred to a future milestone.

---

## Problem Frame

The Rust `PluginManager` can load plugins implemented in Rust. Existing CPEX deployments have Python plugin classes (identity resolvers, token delegators, custom hook handlers) that must continue to work without modification. Issue #19 established the Python bindings foundation; this work surfaces it to Rust callers through the plugin factory system.

The subprocess-isolated model is chosen over in-process PyO3 to:
- Avoid introducing a libpython dependency into the default Rust build
- Reuse the battle-tested `worker.py` / `VenvProcessCommunicator` protocol already in production
- Guarantee that plugin venv dependencies cannot conflict with host site-packages

---

## Requirements Trace

| Criterion | Source |
|---|---|
| `kind: "python-isolated://module.ClassName"` loads Python plugin | AC-8 |
| Venv created once on `initialize()`, reused via requirements-hash cache | AC-9 |
| `shutdown()` sends shutdown task, waits 5 s, then kills | AC-10 |
| Payload serialization uses JSON (no MessagePack) | AC-11 |
| `on_error` behavior (`fail` / `ignore` / `disable`) honoured on Python exceptions | AC-5 |
| `initialize()` / `shutdown()` Python methods called if defined; missing = no-op | AC-6 |
| Crate in `[workspace] members` but not `default-members` | AC-7 |
| `PluginResult` fields (`continue_processing`, `modified_payload`, `violation`) mapped correctly | AC-3, AC-4 |

---

## Key Technical Decisions

**1. Subprocess protocol reuse, no new wire format.**  
`worker.py` already implements `load_and_run_hook` over JSON-lines stdin/stdout with request-ID-based demultiplexing. The Rust adapter replicates `VenvProcessCommunicator`'s subprocess lifecycle using `tokio::process::Command` and drives the same task dict. No new serialization layer needed; `serde_json` suffices.

**2. `AnyHookHandler` hook-name binding.**  
`AnyHookHandler::invoke` does not receive the hook name at call time — the handler is pre-bound via `hook_type_name() -> &'static str`. The factory reads hook names from YAML `config.hooks` and uses `Box::leak` (same pattern as `apl-pii-scanner`) to produce `'static str` keys. It populates `PluginInstance.handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)>` and returns it; the manager calls `register_multi_handler` internally — the factory never calls the registry directly.

**3. Payload serialization via per-hook static dispatch functions.**  
`PluginPayload` has no `Serialize` bound — it is object-safe by design and `erased-serde` cannot be used on `&dyn PluginPayload` without breaking that contract. Serialization is performed by a `HookPayloadRegistry`: two `HashMap<&'static str, fn(...)>` maps (one for serialize, one for deserialize) keyed by hook type name. Each entry is a thin shim that downcasts via `as_any().downcast_ref::<ConcreteType>()` and calls `serde_json::to_value` (or `serde_json::from_value`). The registry is a field on `IsolatedPythonPluginAdapter`, populated during `IsolatedPythonPluginAdapterFactory::create` and shared across all handler entries via `Arc`. Private credential fields marked `#[serde(skip)]` remain on the Rust side.

**4. `ErasedResultFields` constructed directly; registry shared via `Arc`.**  
The adapter's `invoke()` returns `Box::new(ErasedResultFields { ... })` (`cpex_core::executor::ErasedResultFields` is `pub`) rather than `erase_result::<P>()`, since the concrete payload type is not statically known at the Python boundary. `PluginInstance` carries only `plugin` and `handlers` — no third field exists. Auxiliary state (the payload registry) lives on the adapter struct; the `Arc<IsolatedPythonPluginAdapter>` cloned into each `handlers` entry naturally shares it at no extra cost.

**5. `venv_path` defaults, YAML override optional.**  
Default: `<first plugin_dir>/<class_root>/.venv` — matching `IsolatedVenvPlugin`. An optional `config.venv_path` YAML key overrides it. Requirements-hash cache metadata lives at `<venv_path>/../.cpex/venv_cache/<venv_name>_metadata.json` (same layout as Python side).

**6. `tokio` `process` feature.**  
The workspace `tokio` declaration omits the `process` feature. The new crate's `Cargo.toml` adds `tokio = { workspace = true, features = ["process"] }` to activate it via Cargo feature unification — existing crates are unaffected.

**7. Payload deserialization routing.**  
The adapter stores a `hook_name → deserialize_fn` map populated at construction time from a registry of known payload types. Unknown hook names fall back to a `GenericPayload(serde_json::Value)` wrapper that satisfies `PluginPayload` and passes through unmodified. This defers the CMF `MessagePayload` special-case (open question in origin doc) to implementation-time lookup rather than speculative code now.

---

## Scope Boundaries

### In scope
- `crates/cpex-hosts-python` crate with `IsolatedPythonPluginAdapter` and its factory
- Subprocess lifecycle: venv create/cache, worker spawn, graceful shutdown with kill fallback
- JSON-lines dispatch reusing `worker.py` `load_and_run_hook` protocol
- `PluginResult` fields mapped to `ErasedResultFields`
- `on_error` (`fail` / `ignore` / `disable`) behaviour on Python exceptions
- Workspace plumbing: `Cargo.toml` members, `tokio` feature extension, CI comment
- Integration tests against a minimal Python plugin fixture

### Deferred to Follow-Up Work
- In-process `python://` adapter (PyO3) — deferred by user decision
- Bidirectional payloads for hooks not yet in cpex-core
- Hot-reload of Python plugins at runtime
- Type stub generation for the adapter crate

### Out of scope
- Modifying `worker.py` or `VenvProcessCommunicator` — Rust adapter consumes them as-is
- Python-side changes to `IsolatedVenvPlugin`
- Changes to `cpex-ffi` or the Go bindings layer

---

## High-Level Technical Design

### Subprocess lifecycle

```
PluginManager::initialize()
  └─► IsolatedPythonPluginAdapter::initialize()
        ├─ compute requirements hash
        ├─ if hash unchanged and .venv exists → reuse
        ├─ else → create venv, pip install, save metadata
        └─ spawn worker.py subprocess (tokio::process::Command)
              stdin/stdout pipes open, stderr logged

PluginManager::invoke_by_name("hook_name", payload, extensions, ctx)
  └─► IsolatedPythonPluginAdapter::invoke(payload, extensions, ctx)
        ├─ registry.serialize(hook_name, payload)  → task["payload"]
        ├─ write JSON-lines task to worker stdin  (+ request_id)
        ├─ await response line from stdout channel
        ├─ deserialize response → ErasedResultFields
        └─ return Box::new(erased_fields)

PluginManager::shutdown()
  └─► IsolatedPythonPluginAdapter::shutdown()
        ├─ send {"task_type":"shutdown","request_id":"shutdown"}
        ├─ wait up to 5 s
        └─ kill() if timeout
```

### Factory registration flow

```
// Host at startup:
let mut factories = PluginFactoryRegistry::new();
factories.register(
    cpex_hosts_python::isolated::KIND,   // "python-isolated://"
    Box::new(IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default())),
    // HookPayloadRegistry::default() covers all built-in cpex-core payload types.
    // Hosts with custom payload types must extend the registry before passing it in.
);
let manager = PluginManager::from_config(path, &factories)?;

// YAML config consumed by factory:
//   kind: "python-isolated://my_pkg.MyPlugin"
//   config:
//     requirements_file: plugins/my_pkg/requirements.txt
//     venv_path: plugins/my_pkg/.venv     # optional

// Factory extracts URI host+path as class_name,
// Box::leaks each hook name from config.hooks,
// returns PluginInstance { plugin: adapter, handlers: [(leaked_name, Arc<adapter>), ...] }
```

### Response → ErasedResultFields mapping

`ErasedResultFields` has four fields (`executor.rs:1029–1034`); all must be supplied:

| Worker response field | ErasedResultFields field | Notes |
|---|---|---|
| `continue_processing: bool` | `continue_processing` | Direct |
| `violation: {message, ...}` | `violation: Some(PluginViolation)` | Present when plugin denied; `PluginViolation` already derives `Deserialize` |
| `modified_payload: dict \| null` | `modified_payload: Option<Box<dyn PluginPayload>>` | Deserialized via hook-name router |
| _(not in worker protocol)_ | `modified_extensions: None` | Python plugins cannot modify `Extensions`; always `None` for this adapter |
| `status: "error"` / exception | → `Box<PluginError>` propagated | Triggers `on_error` in executor |

Note: the raw JSON response from `worker.py` stdout **contains** `request_id` at the top level (`worker.py:196`). The Rust background reader must use it for demultiplexing and must NOT strip it before routing — unlike `VenvProcessCommunicator.send_task` which pops it on the Python side after routing.

---

## Output Structure

```
crates/cpex-hosts-python/
├── Cargo.toml
└── src/
    ├── lib.rs               # pub use isolated::*; crate-level docs
    ├── isolated/
    │   ├── mod.rs           # pub use adapter::*, factory::*
    │   ├── adapter.rs       # IsolatedPythonPluginAdapter: Plugin + AnyHookHandler
    │   ├── factory.rs       # IsolatedPythonPluginAdapterFactory + KIND constant
    │   ├── subprocess.rs    # WorkerProcess: spawn, send_task, shutdown
    │   ├── venv.rs          # venv creation, requirements-hash cache
    │   └── payload.rs       # payload_to_json, json_to_erased, hook-name deserializer map
    └── tests/
        └── isolated_e2e.rs  # integration test against echo_plugin.py fixture
```

Python test fixture (not a Rust source file — lives alongside the integration test):

```
crates/cpex-hosts-python/tests/
├── isolated_e2e.rs
└── fixtures/
    ├── echo_plugin.py          # minimal @hook plugin that echoes payload
    └── requirements.txt        # empty (no deps beyond cpex)
```

---

## Implementation Units

### U1. Workspace scaffolding

**Goal:** Add `crates/cpex-hosts-python` to the workspace and establish the Cargo manifest with correct dependency declarations.

**Requirements:** AC-7 (not in `default-members`)

**Dependencies:** none

**Files:**
- `Cargo.toml` — add `crates/cpex-hosts-python` to `[workspace].members`; do not add to `default-members`
- `crates/cpex-hosts-python/Cargo.toml` — new file
- `crates/cpex-hosts-python/src/lib.rs` — crate root, empty re-exports for now

**Approach:**  
`Cargo.toml` for the new crate declares `cpex-core` as a path dependency, adds `tokio = { workspace = true, features = ["process"] }`, `serde_json = { workspace = true }`, `serde = { workspace = true }`, `async-trait = { workspace = true }`, `thiserror = { workspace = true }`, `tracing = { workspace = true }`. No pyo3 anywhere. The crate compiles clean with an empty lib.rs before any implementation begins.

**Patterns to follow:** `crates/apl-pii-scanner/Cargo.toml` for workspace dep declarations; `apl-cedarling` exclusion from `default-members` for the workspace pattern.

**Test scenarios:**
- `cargo build -p cpex-hosts-python` succeeds on a machine with no libpython installed
- `cargo build` (default members only) still succeeds and does not include `cpex-hosts-python`
- `cargo build --workspace` includes the crate

**Verification:** `cargo build -p cpex-hosts-python` exits 0; `cargo build` (no `-p`) does not list `cpex-hosts-python` in its compile units.

---

### U2. Venv lifecycle module

**Goal:** Implement the venv creation and requirements-hash cache logic that `IsolatedPythonPluginAdapter` calls on `initialize()`.

**Requirements:** AC-9

**Dependencies:** U1

**Files:**
- `crates/cpex-hosts-python/src/isolated/venv.rs` — new
- `crates/cpex-hosts-python/src/isolated/mod.rs` — new (pub mod venv)

**Approach:**  
`VenvManager` struct holds `venv_path: PathBuf`, `requirements_file: PathBuf`, `cache_metadata_path: PathBuf`. `ensure_venv()` is async: reads the metadata JSON, computes SHA-256 of the requirements file (or empty bytes if absent), compares with stored hash — if match, returns `VenvState::Reused`; otherwise creates venv via `std::process::Command` (`python3 -m venv <path>`), runs `pip install -r`, writes metadata JSON, returns `VenvState::Created`. Metadata JSON schema mirrors Python: `{venv_path, requirements_file, requirements_hash, python_version}`. `python_executable()` returns the platform-correct path (`<venv>/bin/python` on Unix, `<venv>/Scripts/python.exe` on Windows).

**Patterns to follow:** `cpex/framework/isolated/client.py` — `_compute_requirements_hash`, `_is_venv_cache_valid`, `_save_cache_metadata`, `create_venv`.

**Test scenarios:**
- Fresh venv: no `.venv` dir → `ensure_venv()` creates it, installs requirements, writes metadata, returns `Created`
- Cache hit: `.venv` exists and hash matches → `ensure_venv()` returns `Reused` without running pip
- Cache miss: `.venv` exists but requirements file has changed → removes old venv, recreates, returns `Created`
- Missing requirements file: treated as empty hash (no pip install step), venv still created
- `python_executable()` returns a path that exists after `ensure_venv()`

**Verification:** Unit tests in `venv.rs` using a temp directory; no network access needed since requirements.txt is empty in fixtures.

---

### U3. Worker subprocess module

**Goal:** Implement the long-running subprocess lifecycle: spawn, send/receive JSON-lines tasks with request-ID demux, graceful shutdown.

**Requirements:** AC-10, AC-11

**Dependencies:** U2

**Files:**
- `crates/cpex-hosts-python/src/isolated/subprocess.rs` — new

**Approach:**  
`WorkerProcess` struct holds a `tokio::process::Child`, a `tokio::sync::mpsc::Sender<WorkerTask>` where `WorkerTask = (String /* request_id */, serde_json::Value, oneshot::Sender<Result<serde_json::Value, WorkerError>>)`. A background `tokio::task` owns the child's stdin/stdout: it receives tasks from the mpsc channel, writes `{...task_data, "request_id": id}\n` to stdin, reads response lines from stdout, demultiplexes by `request_id`, and sends the response back on the oneshot.

`WorkerProcess::spawn(python_exe, script_path, cwd)` starts the child with `stdin(Stdio::piped())`, `stdout(Stdio::piped())`, `stderr(Stdio::piped())`, spawns the background reader/writer task.

`WorkerProcess::send_task(task_data, timeout)` generates a UUID request_id, registers a oneshot, sends on the mpsc channel, awaits the oneshot with timeout.

`WorkerProcess::shutdown(timeout_secs)` sends `{"task_type":"shutdown","request_id":"shutdown"}` via `send_task`, waits, then calls `child.kill()` if the process hasn't exited within `timeout_secs`. `WorkerProcess` also implements `Drop` to send the shutdown line and call `child.kill()` synchronously — this prevents subprocess orphans if the adapter is dropped without an explicit `shutdown()` call.

**Patterns to follow:** `cpex/framework/isolated/venv_comm.py` — `start_worker`, `send_task`, `stop_worker`, `_read_responses`; adapt the threading model to tokio tasks.

**Test scenarios:**
- Spawn + send `{"task_type":"info"}` → worker returns environment info JSON
- Request-ID routing: two concurrent tasks return responses to the correct callers
- Timeout: a task that never responds returns `WorkerError::Timeout` after the configured duration
- Graceful shutdown: send shutdown task → worker process exits within 5 s, child handle cleaned up
- Kill fallback: if shutdown task times out, `child.kill()` is called and the process is gone
- Stderr from worker is captured and logged at `tracing::debug` level (not silently dropped)
- Worker process crash mid-invocation: outstanding oneshots receive `WorkerError::ProcessDied`
- Drop without `shutdown()`: `WorkerProcess::drop` kills the child process; no zombie in process table after drop

**Verification:** Integration test spawning a real `worker.py` subprocess (requires Python in PATH); use the `echo_plugin.py` fixture from `tests/fixtures/`.

---

### U4. Payload serialization module

**Goal:** Serialize `&dyn PluginPayload` to JSON for the task dict, and deserialize the worker's response payload JSON back to `Box<dyn PluginPayload>`.

**Requirements:** AC-3, AC-4, AC-11

**Dependencies:** U1

**Files:**
- `crates/cpex-hosts-python/src/isolated/payload.rs` — new

**Approach:**  
`payload.rs` defines two function type aliases: `SerializeFn = fn(&dyn PluginPayload) -> serde_json::Value` and `DeserializeFn = fn(serde_json::Value) -> Box<dyn PluginPayload>`. It also defines `HookPayloadRegistry { serialize: HashMap<&'static str, SerializeFn>, deserialize: HashMap<&'static str, DeserializeFn> }`.

Each concrete payload type contributes one pair of shims: `serialize_shim` downcasts via `as_any().downcast_ref::<ConcreteType>().expect(...)` and calls `serde_json::to_value`; `deserialize_shim` calls `serde_json::from_value::<ConcreteType>()` and boxes the result. Unknown hook names fall back to a `GenericPayload(serde_json::Value)` passthrough wrapper.

`json_to_erased` takes `registry: &HookPayloadRegistry, hook_name: &str, response: serde_json::Value` and produces `ErasedResultFields` directly (no `erase_result` call). `PluginViolation` already derives `Serialize, Deserialize` (confirmed in `cpex-core/src/error.rs:214`).

**Patterns to follow:** `crates/cpex-core/src/executor.rs:1029–1065` (`ErasedResultFields`, `erase_result`, `extract_erased`); `crates/cpex-core/src/hooks/trait_def.rs` (`PluginResult` constructors).

**Test scenarios:**
- `payload_to_json` on a `MessagePayload` produces a JSON object with expected top-level keys
- `payload_to_json` on a payload with `#[serde(skip)]` private fields does not include those fields
- `json_to_erased` with `continue_processing: true`, no violation, no modified payload → allow result
- `json_to_erased` with `continue_processing: false` and a violation dict → deny result with `PluginViolation`
- `json_to_erased` with `modified_payload` for a known hook → returns `Some(Box<dyn PluginPayload>)` with correct concrete type
- `json_to_erased` with `modified_payload` for an unknown hook name → returns `GenericPayload` passthrough wrapper, does not panic
- Round-trip: serialize a `MessagePayload` to JSON via `serialize_shim`, deserialize back via `deserialize_shim`, key fields match
- `PluginViolation` round-trips through JSON without adding `#[derive(Deserialize)]` (it already exists)

**Verification:** Unit tests in `payload.rs`; no subprocess needed.

---

### U5. `IsolatedPythonPluginAdapter` and factory

**Goal:** Implement the `Plugin` lifecycle and `AnyHookHandler` dispatch for the subprocess-isolated adapter, and the `PluginFactory` that constructs it from YAML config.

**Requirements:** AC-5, AC-6, AC-8, AC-9, AC-10

**Dependencies:** U2, U3, U4

**Files:**
- `crates/cpex-hosts-python/src/isolated/adapter.rs` — new
- `crates/cpex-hosts-python/src/isolated/factory.rs` — new
- `crates/cpex-hosts-python/src/isolated/mod.rs` — updated (pub mod adapter, factory)
- `crates/cpex-hosts-python/src/lib.rs` — updated (pub use isolated::{KIND, IsolatedPythonPluginAdapterFactory})

**Approach:**

`IsolatedPythonPluginAdapter` holds: `config: PluginConfig`, `venv_manager: VenvManager`, `worker: tokio::sync::Mutex<Option<WorkerProcess>>`, `hook_payload_registry: Arc<HookPayloadRegistry>`, `class_name: String`, `plugin_dirs: Vec<String>`.

`Plugin::initialize()`: calls `venv_manager.ensure_venv().await`, then `WorkerProcess::spawn(...)` and stores in `worker`. Also sends a `load_and_run_hook`-style init call if the Python class defines `initialize()` — or more simply, the first hook invocation triggers lazy initialization via the worker's existing caching logic (since `worker.py` caches the plugin after first load). This matches existing Python behavior.

`Plugin::shutdown()`: locks `worker`, calls `WorkerProcess::shutdown(5)`, sets to `None`.

`AnyHookHandler::invoke(payload, extensions, ctx)`:
1. Serialize payload via `payload_to_json`
2. Serialize `PluginContext` state fields to JSON (only `state` and `global_context` — same as Python `_build_hook_task`)
3. Build task dict: `{task_type, plugin_dirs, class_name, config: safe_config_json, hook_type, plugin_name, payload, context, request_id}`
4. Call `worker.send_task(task, timeout)` — await response
5. On worker error: construct `Box<PluginError>` and return `Err(...)` — executor's `on_error` handling takes over
6. On success: call `json_to_erased(hook_name, response)` and return `Ok(Box::new(erased))`

`hook_type_name()`: returns the hook name this handler instance was pre-bound to (stored as `&'static str` via `Box::leak` at factory construction time).

`IsolatedPythonPluginAdapterFactory`:
- `pub const KIND: &str = "python-isolated"`
- Initialized with a `HookPayloadRegistry` (or constructs a built-in default registry covering all known cpex-core payload types). The registry is `Arc`-wrapped.
- `create(config)` parses the URI path from `config.kind` (strip `python-isolated://` prefix → `class_name`), reads `config.config["requirements_file"]`, optionally `config.config["venv_path"]`, builds `VenvManager`, constructs one `IsolatedPythonPluginAdapter` (with `Arc::clone(&self.registry)`) wrapped in `Arc`, then for each hook name in `config.hooks` leaks the string (`Box::leak(h.clone().into_boxed_str())` — same pattern as `apl-pii-scanner`) and registers the same adapter as handler. Returns `PluginInstance { plugin: adapter, handlers }`.
- Validates: `config.hooks` must be non-empty; `requirements_file` treated as empty if absent (no pip install step).

**Patterns to follow:** `crates/apl-pii-scanner/src/factory.rs` (canonical factory with `Box::leak`); `crates/cpex-core/src/plugin.rs` (`Plugin` trait via `#[async_trait]`); `cpex/framework/isolated/client.py` (`invoke_hook`, `_build_hook_task`).

**Test scenarios:**
- `create()` with a valid config → `PluginInstance` with one `Arc<IsolatedPythonPluginAdapter>` and N handler entries matching `config.hooks`
- `create()` with empty `hooks` list → returns `Err(PluginError::Config)`
- `create()` with kind `"python-isolated://my_pkg.MyPlugin"` → `class_name == "my_pkg.MyPlugin"`
- `initialize()` creates the `.venv` directory and starts the worker subprocess
- `invoke()` sends a task and receives a result with `continue_processing: true` (happy path)
- Python exception in worker → `invoke()` returns `Err(PluginError)`, executor applies `on_error`
- `on_error: disable` → second invocation skips the plugin (circuit-breaker via `PluginRef::disable`)
- `shutdown()` terminates the worker process; subsequent `invoke()` after shutdown fails gracefully
- `hook_type_name()` returns the hook name the handler was registered for, not the plugin name

**Verification:** Unit tests for the factory; integration test in `tests/isolated_e2e.rs` (U6).

---

### U6. Integration test

**Goal:** End-to-end test: load a real Python plugin class through the Rust `PluginManager` using `kind: "python-isolated://"` config.

**Requirements:** AC-3, AC-4, AC-5, AC-6, AC-8, AC-9, AC-10, AC-11

**Dependencies:** U5

**Files:**
- `crates/cpex-hosts-python/tests/isolated_e2e.rs` — new
- `crates/cpex-hosts-python/tests/fixtures/echo_plugin.py` — new Python fixture
- `crates/cpex-hosts-python/tests/fixtures/requirements.txt` — new (empty)

**Approach:**  
`echo_plugin.py` is a minimal CPEX plugin class with `@hook("tool_pre_invoke")` on a method that returns `PluginResult.allow()` unchanged, and a second variant that returns `PluginResult.modify(payload)` with a field mutated. Also a variant that raises `RuntimeError` to test `on_error`. `initialize()` and `shutdown()` methods are present but no-op.

The test builds a `PluginFactoryRegistry`, registers `IsolatedPythonPluginAdapterFactory` under `KIND`, constructs a `PluginConfig` inline (pointing `plugin_dirs` at `tests/fixtures/`, `class_name` at `echo_plugin.EchoPlugin`, empty `requirements.txt`), calls `manager.initialize().await`, invokes the hook with a `ToolPreInvokePayload` (or generic payload), and asserts the result.

Tests gated behind `#[cfg(target_os = "linux")]` or behind a `with-python` Cargo feature to avoid failing on CI machines without Python — add a note in `README.md` (or test module docstring) about the requirement. Alternatively, use `std::process::Command::new("python3").arg("--version")` to skip gracefully.

**Patterns to follow:** `crates/cpex-core/tests/identity_e2e.rs` (manager setup, `#[tokio::test]`, inline `PluginConfig`).

**Test scenarios:**
- Covers AC-8: plugin loaded via `kind: "python-isolated://echo_plugin.EchoPlugin"` and invoked successfully
- Covers AC-9: second invocation reuses venv (no pip re-run); assert metadata file present and unchanged
- Covers AC-3/AC-4: `allow()` result → `continue_processing: true`, no modified payload
- Covers AC-3/AC-4: `modify(payload)` result → `modified_payload` present in `PipelineResult`
- Covers AC-5: Python `RuntimeError` → `on_error: fail` propagates error to caller
- Covers AC-6: `initialize()` / `shutdown()` called on Python class; missing methods are no-op (use a plugin class without those methods)
- Covers AC-10: `manager.shutdown()` terminates the worker process within 5 s

**Verification:** `cargo test -p cpex-hosts-python` passes when Python 3.11+ is available. Test skips gracefully when Python is absent.

---

## System-Wide Impact

- **Unregistered kind → hard error.** `PluginManager::load_config` calls `factories.get(&kind)` and returns `PluginError::Config` if the kind is absent — it does not silently skip. Any host using `python-isolated` in YAML must call `manager.register_factory("python-isolated", Box::new(IsolatedPythonPluginAdapterFactory::new(...)))` before `load_config`. Misconfigured hosts fail fast at startup, not at first invocation.
- **Drop without `shutdown` orphans subprocesses.** `WorkerProcess` must implement `Drop` to send `{"task_type":"shutdown"}` and then call `child.kill()` — without it, the OS-level worker process outlives the Rust `PluginManager` drop. Pure-Rust adapters have no subprocess to orphan; this adapter imposes a stronger resource-cleanup obligation than existing plugin kinds.
- **Subprocess count scales T×N under multi-tenancy.** Each `PluginManager::load_config` call creates a new `IsolatedPythonPluginAdapter` (and one subprocess) per plugin config entry. If a tenant-scoped Rust `PluginManager` is added in the future (analogous to Python's `TenantPluginManager`), T tenants × N `python-isolated` plugins = T×N subprocesses. No subprocess sharing across `PluginManager` instances exists; operators must size `RLIMIT_NPROC` and file-descriptor limits accordingly.
- **`cpex-orchestration` unaffected.** `cpex-orchestration` is a domain-agnostic `run_branches` primitive with no knowledge of plugin kinds, factory registries, or subprocess management. No changes needed.
- **Workspace CI.** Adding `crates/cpex-hosts-python` to `[workspace] members` enrolls it in `cargo test --workspace`. The `tokio "process"` feature is absent from the workspace-level tokio declaration; the new crate must activate it in its own `Cargo.toml` (`tokio = { workspace = true, features = ["process"] }`). Feature unification is additive — no impact on existing crates.

---

## Open Questions

| Question | Status | Notes |
|---|---|---|
| Does `PluginViolation` derive `Deserialize`? | **Resolved** — yes | `#[derive(Serialize, Deserialize)]` confirmed at `crates/cpex-core/src/error.rs:214`. No changes to cpex-core needed. |
| Should `PluginContext::state` / `global_context` be sent to worker? | Resolve at U5 | Python `_build_hook_task` sends both; verify `PluginContext` fields are `serde_json`-serializable |
| CMF `MessagePayload` special-case serialization? | Deferred — all built-in payloads are serde-compatible; no special treatment anticipated | If a non-serializable payload type is added later, the `serialize_fn` map in U4 handles it without adapter changes |
| `venv_path` YAML override — required or optional? | Optional, defaults to `<plugin_dir>/<class_root>/.venv` | Match `IsolatedVenvPlugin` behaviour; document in factory `create()` |

---

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Python 3.11+ not available in CI | Medium | Integration tests silently skip or fail | Gate test behind Python version check; document requirement |
| `worker.py` imports cpex Python package — not installed in test venv | High | Integration test fails at worker startup | Test fixture `requirements.txt` must install cpex from the local path; handle in venv setup |
| `tokio::process` feature unification breaks existing crates | Low | Cargo build error | Feature is additive; only adds process-related tokio internals, no API changes for existing crates |
| `WorkerProcess` drop without `shutdown` — subprocess leak | Medium | OS-level orphan process | `WorkerProcess` must implement `Drop` with `kill()` call (see System-Wide Impact); document in U3 |
| `PluginContext` not fully JSON-serializable | Low | Runtime serde error | Check `PluginContext` fields before U5; add `#[serde(skip)]` or `Default` impls if needed |

---

## Sources & Research

- `crates/cpex-core/src/registry.rs:182–197` — `AnyHookHandler` trait signature
- `crates/cpex-core/src/factory.rs` — `PluginFactory`, `PluginInstance`, `PluginFactoryRegistry`
- `crates/cpex-core/src/executor.rs:1029–1065` — `ErasedResultFields`, `erase_result`, `extract_erased`
- `crates/cpex-core/src/executor.rs:400–520` — `run_serial_phase` dispatch path, extensions filtering
- `crates/apl-pii-scanner/src/factory.rs:47–63` — canonical `Box::leak` factory pattern; `apl-audit-logger/src/factory.rs:38–48` identical shape
- `crates/cpex-core/src/error.rs:214` — `PluginViolation` derives `Serialize, Deserialize` (confirmed; no cpex-core changes needed)
- `crates/cpex-core/src/manager.rs:322` — `factories.get(&kind).ok_or_else(|| PluginError::Config)` — missing kind is a hard error
- `crates/cpex-core/tests/identity_e2e.rs` — integration test structure
- `cpex/framework/isolated/client.py` — `IsolatedVenvPlugin`, `_build_hook_task`, `invoke_hook`
- `cpex/framework/isolated/venv_comm.py` — `VenvProcessCommunicator` subprocess lifecycle
- `cpex/framework/isolated/worker.py` — `load_and_run_hook` task protocol
- `cpex/framework/decorator.py` — `_HOOK_METADATA_ATTR`, `get_hook_metadata`, `HookMetadata`
