// Location: ./crates/cpex-ffi/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor, Fred Araujo
//
// CPEX FFI — C API for embedding the CPEX runtime.
//
// Exports extern "C" functions that Go (via cgo), Python (via ctypes/cffi),
// and other languages can call. Payloads and extensions cross the boundary
// as MessagePack bytes. ContextTable and BackgroundTasks are opaque handles.
//
// Every engine runs its async work on one process-wide tokio runtime, so
// async plugin execution works from synchronous cgo calls.

use std::os::raw::{c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use praxis_policy_core::context::PluginContextTable;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::BackgroundTasks;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::identity::IdentityPayload;

// Builtin, HTTP transport and secret-provider wiring: the
// `cpex_apl_install` extern "C" entry point.
mod apl;
// Secret refresh and health: `cpex_refresh_secrets` and
// `cpex_secrets_last_success`.
mod secrets;

pub use apl::{CPEX_APL_ALLOW_PRIVATE_DESTINATIONS, CPEX_APL_KNOWN_FLAGS, cpex_apl_install};
pub use secrets::{cpex_refresh_secrets, cpex_secrets_last_success};

// FFI functions return c_int. 0 means success; negative codes classify
// failures so the Go (or other-language) caller can produce a typed
// error rather than a single opaque "invoke failed" string. The codes
// are stable wire ABI — additions go at the end with a fresh value;
// don't renumber.
//
// Mapped on the Go side in `go/cpex/manager.go::errorFromRC`.

/// Operation succeeded.
pub const RC_OK: c_int = 0;
/// Engine handle is null or shut down.
pub const RC_INVALID_HANDLE: c_int = -1;
/// Caller-supplied input is malformed (bad UTF-8, null pointer where
/// data was required, oversized buffer, unknown payload type).
pub const RC_INVALID_INPUT: c_int = -2;
/// Parse / deserialize step failed (YAML config, MessagePack payload,
/// MessagePack extensions).
pub const RC_PARSE_ERROR: c_int = -3;
/// Pipeline / lifecycle step failed: `load_config` returned Err,
/// `initialize` returned Err, or a plugin signalled failure during
/// invoke without a wall-clock timeout or panic.
pub const RC_PIPELINE_ERROR: c_int = -4;
/// Result serialization (post-pipeline) failed — usually OOM on
/// `rmp_serde::to_vec_named` or unserializable JSON value.
pub const RC_SERIALIZE_ERROR: c_int = -5;
/// Wall-clock timeout exceeded inside `run_safely` — plugin likely
/// CPU-bound or blocking the OS thread without yielding.
pub const RC_TIMEOUT: c_int = -6;
/// Plugin panicked; caught by `catch_unwind` at the FFI boundary.
pub const RC_PANIC: c_int = -7;

// The FFI ABI version is an integer that identifies the C-surface
// contract this crate exposes. Bump it on any breaking change to the
// C surface:
//
//   - added / removed / renamed extern "C" function
//   - argument count, argument type, or return type change on an
//     existing function
//   - layout change of a struct that crosses the boundary
//   - semantic change to an existing function (e.g. new RC_* value
//     returned for a previously-success case, change in pointer
//     ownership)
//
// Adding a new RC_* code at the end of the existing range is *not* a
// breaking change (the wire codes are stable; consumers handle unknown
// codes as generic failure).
//
// Consumers — every language binding — MUST call `cpex_ffi_abi_version`
// at init and compare against the version their binding was generated
// for. Mismatch is a hard error: the C surface they generated against
// is not the one they're linked against. Document the binding's
// expected ABI version in its source.
//
// Bumps are recorded in CHANGELOG.md under "Changed" with the from→to
// integers and a one-line description of what moved.

/// FFI ABI version. Bump on breaking C-surface changes; see module
/// docs above for what counts as breaking.
pub const FFI_ABI_VERSION: u32 = 3;

/// Returns the FFI ABI version this `libcpex_ffi` was built with.
/// Language bindings call this at `init` and panic on mismatch
/// against the version they were generated for.
///
/// Pure const access — no allocation, no runtime, no panics. Safe to
/// call from anywhere including signal handlers.
#[unsafe(no_mangle)]
pub extern "C" fn cpex_ffi_abi_version() -> u32 {
    FFI_ABI_VERSION
}

/// Outer wall-clock timeout for any FFI-driven async call. Per-plugin
/// `tokio::time::timeout` only catches cooperative-async timeouts; this
/// catches CPU-bound or thread-blocking plugins that never yield. Set
/// generously — bigger than any reasonable per-plugin timeout — so the
/// usual case never hits this bound.
const FFI_WALL_CLOCK_TIMEOUT: Duration = Duration::from_secs(60);

// One process-singleton runtime serves every engine rather than each
// `cpex_engine_new` building its own. With many engines (multi-tenant
// hosts that create one per request, dynamic plugin reload, etc.) the
// per-engine model exploded thread count: 100 engines × num_cpus
// workers each = hundreds of OS threads (and ~2MB stack apiece).
//
// Worker thread count precedence (highest first):
//   1. `cpex_configure_runtime(N)` — explicit FFI call, before first use.
//   2. `CPEX_FFI_WORKER_THREADS` env var — operator-friendly; read once
//      on first use of `shared_runtime()`.
//   3. tokio default (`num_cpus`).
//
// Once the runtime is initialized it's fixed for the process lifetime.
static SHARED_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Name of the env var operators set to bound worker threads without
/// recompiling host code or touching YAML.
const ENV_WORKER_THREADS: &str = "CPEX_FFI_WORKER_THREADS";

/// Parse `CPEX_FFI_WORKER_THREADS` if set. Returns `Some(n)` for valid
/// positive integers, `None` for unset / zero / negative / unparseable
/// values (in which case the runtime falls back to tokio's default).
/// Logs a warning on malformed values so operators see why their
/// setting was ignored.
///
/// Extracted from `shared_runtime` so it's unit-testable without
/// touching the global `OnceLock`.
fn worker_threads_from_env() -> Option<usize> {
    parse_worker_threads(&std::env::var(ENV_WORKER_THREADS).ok()?)
}

/// Parse a raw `CPEX_FFI_WORKER_THREADS` value. Split from
/// `worker_threads_from_env` so tests can cover the parsing without
/// mutating the process environment, which is unsound while other test
/// threads may read it.
fn parse_worker_threads(raw: &str) -> Option<usize> {
    match raw.parse::<usize>() {
        Ok(n) if n > 0 => Some(n),
        Ok(_) => {
            tracing::warn!(
                "cpex-ffi: {}={} is not a positive integer; using num_cpus default",
                ENV_WORKER_THREADS,
                raw,
            );
            None
        },
        Err(_) => {
            tracing::warn!(
                "cpex-ffi: {}={:?} is not parseable as a positive integer; using num_cpus default",
                ENV_WORKER_THREADS,
                raw,
            );
            None
        },
    }
}

/// Get (or lazily initialize on first call) the shared tokio runtime.
///
/// On first call: respects `CPEX_FFI_WORKER_THREADS` if set. If the env
/// var is absent or invalid, defaults to tokio's `num_cpus`. The FFI
/// path `cpex_configure_runtime` overrides both — it `set`s the
/// OnceLock before this function is called, so by the time
/// `get_or_init` runs the runtime is already there and the env var is
/// ignored.
fn shared_runtime() -> &'static tokio::runtime::Runtime {
    SHARED_RUNTIME.get_or_init(|| {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        if let Some(n) = worker_threads_from_env() {
            builder.worker_threads(n);
            tracing::info!(
                "cpex-ffi: shared runtime using {} worker threads (from {})",
                n,
                ENV_WORKER_THREADS,
            );
        }
        builder
            .build()
            .expect("cpex-ffi: failed to build shared tokio runtime")
    })
}

/// Configure the shared tokio runtime's worker thread count.
///
/// Must be called *before* any `cpex_engine_new` / `cpex_engine_new_default`
/// call: once an engine has been created the runtime is fixed for
/// the process lifetime. Returns `RC_OK` on success or
/// `RC_INVALID_INPUT` if the runtime has already been initialized
/// (or if `worker_threads` is non-positive).
///
/// Use case: multi-tenant hosts that want to bound total worker
/// threads regardless of how many `PolicyEngine`s are alive.
///
/// Precedence: this FFI call beats `CPEX_FFI_WORKER_THREADS` (the env
/// var is read only on lazy init via `shared_runtime()`; an explicit
/// `set` here populates the OnceLock first and short-circuits that
/// path). Operators can set the env var as a default; host code can
/// override.
///
/// # Safety
/// Safe to call from a single thread before any engine creation.
/// Calling after an engine exists is well-defined (returns
/// `RC_INVALID_INPUT`) but does not change the active runtime.
#[unsafe(no_mangle)]
pub extern "C" fn cpex_configure_runtime(worker_threads: c_int) -> c_int {
    if worker_threads <= 0 {
        return RC_INVALID_INPUT;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads as usize)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("cpex_configure_runtime: build failed: {}", e);
            return RC_PIPELINE_ERROR;
        },
    };
    match SHARED_RUNTIME.set(rt) {
        Ok(()) => RC_OK,
        Err(_) => {
            // Runtime already initialized — caller should have set
            // this before any engine creation.
            tracing::warn!(
                "cpex_configure_runtime: runtime already initialized; \
                 configuration ignored. Call before any cpex_engine_new.",
            );
            RC_INVALID_INPUT
        },
    }
}

/// Outcome of `run_safely`. Lets the caller distinguish timeout vs.
/// panic so they can return the right `RC_*` code instead of collapsing
/// both into a generic failure.
enum SafeRun<T> {
    Ok(T),
    Timeout,
    Panicked,
}

impl<T> SafeRun<T> {
    /// Code to return from the FFI function on a non-Ok outcome.
    /// On `Ok(_)` callers continue with the wrapped value; this is only
    /// consulted on the failure paths.
    fn rc(&self) -> c_int {
        match self {
            SafeRun::Ok(_) => RC_OK,
            SafeRun::Timeout => RC_TIMEOUT,
            SafeRun::Panicked => RC_PANIC,
        }
    }
}

/// Run a future on the shared tokio runtime with two layers of safety:
///
/// 1. `tokio::time::timeout` bounds the total wall-clock time. A plugin
///    that blocks an OS thread (rather than awaiting cooperatively) will
///    eventually surface as `Err(Elapsed)` here instead of hanging the
///    calling goroutine forever.
/// 2. `std::panic::catch_unwind` converts any panic that escapes the
///    pipeline into an `Err`, preventing it from unwinding across the
///    `extern "C"` boundary (which is UB on Rust < 1.81 and an abort on
///    >= 1.81).
///
/// Returns a `SafeRun<T>` so the caller can map the failure shape to a
/// specific `RC_*` code.
fn run_safely<F, T>(fut: F, op_name: &str) -> SafeRun<T>
where
    F: std::future::Future<Output = T>,
{
    // `tokio::time::timeout` must be constructed inside an active runtime
    // context — it registers a timer with the runtime's timer driver.
    // Wrap construction in an `async` block so it happens INSIDE block_on,
    // not before. (Constructing it outside panics with "there is no
    // reactor running".)
    let result = catch_unwind(AssertUnwindSafe(|| {
        shared_runtime()
            .block_on(async move { tokio::time::timeout(FFI_WALL_CLOCK_TIMEOUT, fut).await })
    }));
    match result {
        Ok(Ok(value)) => SafeRun::Ok(value),
        Ok(Err(_elapsed)) => {
            tracing::error!(
                "FFI {}: wall-clock timeout exceeded ({}s) — plugin likely \
                 not yielding (CPU-bound or std::thread::sleep)",
                op_name,
                FFI_WALL_CLOCK_TIMEOUT.as_secs(),
            );
            SafeRun::Timeout
        },
        Err(_panic_payload) => {
            tracing::error!(
                "FFI {}: plugin panicked across FFI boundary — caught to \
                 prevent UB; returning failure to caller",
                op_name,
            );
            SafeRun::Panicked
        },
    }
}

/// Payload type IDs — must match Go constants.
pub const PAYLOAD_GENERIC: u8 = 0;
pub const PAYLOAD_CMF_MESSAGE: u8 = 1;
/// `IdentityPayload` — the input/output state of the `identity.resolve`
/// hook. Lets non-Rust hosts (the Go bindings) drive identity resolution
/// over the FFI: send the request headers in, read the resolved
/// `subject` / `client` / `raw_credentials` back out (the request
/// headers are not echoed). Without this an
/// FFI host can't run `identity.resolve` (its payload is neither a
/// generic value nor a CMF message), so per-route APL gates that read
/// `subject.*` never see a principal.
pub const PAYLOAD_IDENTITY: u8 = 2;

/// Deserialize a MessagePack payload based on its type ID.
/// Array-indexed — O(1) lookup, zero allocation.
fn deserialize_payload(payload_type: u8, bytes: &[u8]) -> Result<Box<dyn PluginPayload>, String> {
    match payload_type {
        PAYLOAD_GENERIC => {
            let value: serde_json::Value = rmp_serde::from_slice(bytes)
                .map_err(|e| format!("generic payload deserialize failed: {}", e))?;
            Ok(Box::new(GenericPayload { value }))
        },
        PAYLOAD_CMF_MESSAGE => {
            let msg: praxis_policy_core::cmf::MessagePayload = rmp_serde::from_slice(bytes)
                .map_err(|e| format!("CMF payload deserialize failed: {}", e))?;
            Ok(Box::new(msg))
        },
        PAYLOAD_IDENTITY => {
            let idp: IdentityPayload = rmp_serde::from_slice(bytes)
                .map_err(|e| format!("identity payload deserialize failed: {}", e))?;
            Ok(Box::new(idp))
        },
        _ => Err(format!("unknown payload type: {}", payload_type)),
    }
}

/// Refuse a hook name removed in 0.3. Such a name reaches no handler, so
/// dispatching it would return an allow with no policy evaluated. Logs the
/// replacement name.
fn reject_removed_hook(name: &str, op: &str) -> Result<(), c_int> {
    match cpex::host::removed_hook_replacement(name) {
        Some(replacement) => {
            tracing::error!("{}: hook '{}' was removed; use '{}'", op, name, replacement);
            Err(RC_INVALID_INPUT)
        },
        None => Ok(()),
    }
}

/// Refuse an `identity.resolve` input that already carries resolver
/// output (subject, client, claims and so on). Those fields are what the
/// resolvers fill in; a caller that pre-fills them could forge the
/// resolved identity.
fn reject_resolved_identity(idp: &IdentityPayload, op: &str) -> Result<(), c_int> {
    let set = cpex::host::resolved_identity_fields(idp);
    if set.is_empty() {
        return Ok(());
    }
    tracing::error!(
        "{}: identity.resolve input must not set resolver output fields: {}",
        op,
        set.join(", ")
    );
    Err(RC_INVALID_INPUT)
}

/// [`reject_resolved_identity`] for a payload about to be dispatched on
/// `hook_name`: applies only to an `IdentityPayload` on `identity.resolve`.
fn reject_resolved_identity_payload(
    hook_name: &str,
    payload: &dyn PluginPayload,
    op: &str,
) -> Result<(), c_int> {
    if hook_name != praxis_policy_core::identity::HOOK_IDENTITY_RESOLVE {
        return Ok(());
    }
    match payload.as_any().downcast_ref::<IdentityPayload>() {
        Some(idp) => reject_resolved_identity(idp, op),
        None => Ok(()),
    }
}

/// Serialize a modified payload back to MessagePack bytes.
/// Returns the payload type ID alongside the bytes so the caller
/// knows how to deserialize on the other side.
///
/// Errors flow up so the FFI boundary can surface them as a synthetic
/// `PluginErrorRecord` in `result.errors` rather than silently dropping
/// a plugin's modification. Two failure modes:
/// - downcast didn't match any registered type (plugin returned a
///   payload not in the FFI registry)
/// - rmp_serde encoding failed (very unlikely for our known types,
///   but bubble it up rather than swallow it)
fn serialize_payload(payload: &dyn PluginPayload) -> Result<(u8, Vec<u8>), String> {
    // Try CMF MessagePayload first (most common)
    if let Some(mp) = payload
        .as_any()
        .downcast_ref::<praxis_policy_core::cmf::MessagePayload>()
    {
        return rmp_serde::to_vec_named(mp)
            .map(|b| (PAYLOAD_CMF_MESSAGE, b))
            .map_err(|e| format!("CMF payload serialize failed: {e}"));
    }
    // Try GenericPayload
    if let Some(gp) = payload.as_any().downcast_ref::<GenericPayload>() {
        return rmp_serde::to_vec_named(&gp.value)
            .map(|b| (PAYLOAD_GENERIC, b))
            .map_err(|e| format!("generic payload serialize failed: {e}"));
    }
    // Try IdentityPayload: carries the resolved subject, client and claims
    // back to an FFI host after `identity.resolve`. It comes back without
    // its `headers`: they are the request headers the caller passed in,
    // including the credential header (`Authorization` and the like), so
    // echoing them would hand the inbound token back to anything that logs
    // or forwards the result. The raw token field is skip-serialized by PPE.
    if let Some(idp) = payload.as_any().downcast_ref::<IdentityPayload>() {
        let mut value = serde_json::to_value(idp)
            .map_err(|e| format!("identity payload serialize failed: {e}"))?;
        if let serde_json::Value::Object(map) = &mut value {
            map.remove("headers");
        }
        return rmp_serde::to_vec_named(&value)
            .map(|b| (PAYLOAD_IDENTITY, b))
            .map_err(|e| format!("identity payload serialize failed: {e}"));
    }
    Err("unknown payload type, cannot serialize across FFI".to_string())
}

/// Opaque handle to a PolicyEngine.
///
/// All engines share the process-singleton runtime returned by
/// `shared_runtime()`; see the `SHARED_RUNTIME` doc-comment for why.
pub struct CpexEngineInner {
    /// Held as `Arc` so the APL config visitor registered by
    /// `cpex_apl_install` can keep a `Weak<PolicyEngine>` that upgrades
    /// during `load_config_yaml`.
    pub engine: Arc<PolicyEngine>,
    /// Whether `cpex_apl_install` ran on this handle and how it ended. A
    /// mutex rather than an atomic so a concurrent second call waits for
    /// the first to finish instead of returning before the builtins exist.
    install_state: Mutex<apl::InstallState>,
    /// Test-only: makes the next `cpex_apl_install` panic inside its
    /// catch_unwind, to reach the failed state.
    #[cfg(test)]
    fail_install: std::sync::atomic::AtomicBool,
}

impl CpexEngineInner {
    /// Wrap an engine in a fresh handle with nothing installed.
    pub fn new(engine: Arc<PolicyEngine>) -> Self {
        Self {
            engine,
            install_state: Mutex::new(apl::InstallState::NotInstalled),
            #[cfg(test)]
            fail_install: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// Opaque handle to a ContextTable (Rust-owned, not serialized).
pub struct CpexContextTableInner {
    table: PluginContextTable,
}

/// Opaque handle to BackgroundTasks (Rust-owned, not serialized).
pub struct CpexBackgroundTasksInner {
    tasks: BackgroundTasks,
}

unsafe fn c_str_to_slice<'a>(ptr: *const c_char, len: c_int) -> Option<&'a str> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    // SAFETY: `ptr` is non-null and `len` is positive (checked above); the
    // caller guarantees `ptr` points to `len` readable bytes that outlive `'a`.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    std::str::from_utf8(bytes).ok()
}

unsafe fn c_bytes_to_slice<'a>(ptr: *const u8, len: c_int) -> Option<&'a [u8]> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    // SAFETY: `ptr` is non-null and `len` is positive (checked above); the
    // caller guarantees `ptr` points to `len` readable bytes that outlive `'a`.
    Some(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

/// Allocate a byte buffer and return it to the caller.
/// The caller must free it with `cpex_free_bytes`.
///
/// Returns `(null, 0)` for empty input (`std::alloc::alloc` with size=0
/// is UB per its docs) and for buffers that wouldn't fit in `c_int` —
/// `c_int` is i32, so a buffer >= 2 GiB would silently truncate to a
/// negative length and `cpex_free_bytes` would dealloc with the wrong
/// size, corrupting the allocator.
fn alloc_bytes(data: &[u8]) -> (*mut u8, c_int) {
    let len = data.len();
    if len == 0 {
        return (ptr::null_mut(), 0);
    }
    if len > c_int::MAX as usize {
        tracing::error!(
            "alloc_bytes: payload size {} exceeds c_int::MAX ({}); refusing",
            len,
            c_int::MAX,
        );
        return (ptr::null_mut(), 0);
    }
    let layout = std::alloc::Layout::from_size_align(len, 1)
        .expect("align 1 is always valid and len <= c_int::MAX is far under isize::MAX");
    unsafe {
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            return (ptr::null_mut(), 0);
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);
        (ptr, len as c_int)
    }
}

/// Create a new PolicyEngine from a YAML config string.
///
/// Returns an opaque handle, or NULL on failure. No builtins and no HTTP
/// transport are installed on this path: factories must be registered
/// before the config loads, which this one-shot constructor cannot
/// offer. Use `cpex_engine_new_default`, then `cpex_apl_install`, then
/// `cpex_load_config` to get the bundled builtins.
///
/// # Safety
/// `config_yaml` must be a valid pointer to `config_len` bytes of UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_engine_new(
    config_yaml: *const c_char,
    config_len: c_int,
) -> *mut CpexEngineInner {
    // SAFETY: the caller guarantees `config_yaml` is NULL or points to `config_len` readable bytes.
    let yaml = match unsafe { c_str_to_slice(config_yaml, config_len) } {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    let cpex_config = match praxis_policy_core::config::parse_config(yaml) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("cpex_engine_new: config parse failed: {}", e);
            return ptr::null_mut();
        },
    };

    // Touch the shared runtime so any later cpex_configure_runtime
    // call returns RC_INVALID_INPUT — communicates "you missed the
    // window" to the operator, instead of letting the configure call
    // silently no-op.
    let _ = shared_runtime();

    let engine = Arc::new(PolicyEngine::default());

    // This one-shot path uses `load_config` (no visitor walk), so APL is
    // not wired here. APL requires the cpex_engine_new_default, then
    // cpex_apl_install, then cpex_load_config flow.
    if let Err(e) = engine.load_config(cpex_config) {
        tracing::error!("cpex_engine_new: load_config failed: {}", e);
        return ptr::null_mut();
    }

    Box::into_raw(Box::new(CpexEngineInner::new(engine)))
}

/// Create a new PolicyEngine with default config (no YAML).
///
/// Useful when registering plugins programmatically.
#[unsafe(no_mangle)]
pub extern "C" fn cpex_engine_new_default() -> *mut CpexEngineInner {
    let _ = shared_runtime();
    let engine = Arc::new(PolicyEngine::default());
    Box::into_raw(Box::new(CpexEngineInner::new(engine)))
}

/// Load a YAML config into an existing engine.
///
/// Factories must be registered before calling this function.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `handle` must be a valid handle. `config_yaml` must be valid UTF-8.
/// `handle` is `*const`: `PolicyEngine::load_config` takes `&self` after
/// the ArcSwap snapshot refactor (no exclusive access needed). Two
/// callers loading config concurrently is safe; the snapshot swap is
/// atomic copy-on-write, so they see consistent state per call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_load_config(
    handle: *const CpexEngineInner,
    config_yaml: *const c_char,
    config_len: c_int,
) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    // SAFETY: the caller guarantees `config_yaml` is NULL or points to `config_len` readable bytes.
    let yaml = match unsafe { c_str_to_slice(config_yaml, config_len) } {
        Some(s) => s,
        None => return RC_INVALID_INPUT,
    };

    // Validate first (duplicate plugin names, route shape) — preserves the
    // RC_PARSE_ERROR contract. We discard the parsed value and hand the raw
    // YAML to `load_config_yaml`, which re-parses into both a typed
    // PolicyConfig and a raw serde_yaml::Value so registered config visitors
    // (e.g. the APL visitor installed by cpex_apl_install) can walk the
    // `apl:` blocks and install per-route handlers. Plain `load_config`
    // does NOT run that visitor walk.
    if let Err(e) = praxis_policy_core::config::parse_config(yaml) {
        tracing::error!("cpex_load_config: config parse failed: {}", e);
        return RC_PARSE_ERROR;
    }

    // load_config_yaml is sync (no .await), but we still wrap in catch_unwind
    // so a panic in serde / config validation / a visitor doesn't unwind
    // across FFI.
    let load_result = catch_unwind(AssertUnwindSafe(|| inner.engine.load_config_yaml(yaml)));
    match load_result {
        Ok(Ok(())) => RC_OK,
        Ok(Err(e)) => {
            tracing::error!("cpex_load_config: load_config failed: {}", e);
            RC_PIPELINE_ERROR
        },
        Err(_panic) => {
            tracing::error!("cpex_load_config: panic caught at FFI boundary");
            RC_PANIC
        },
    }
}

/// Initialize all registered plugins.
///
/// Returns 0 on success, -1 on failure (including timeout / panic).
///
/// # Safety
/// `handle` must be a valid handle from `cpex_engine_new`.
/// `handle` is `*const`: `PolicyEngine::initialize` takes `&self`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_initialize(handle: *const CpexEngineInner) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    match run_safely(inner.engine.initialize(), "cpex_initialize") {
        SafeRun::Ok(Ok(())) => RC_OK,
        SafeRun::Ok(Err(e)) => {
            tracing::error!("cpex_initialize: {}", e);
            RC_PIPELINE_ERROR
        },
        other => other.rc(), // RC_TIMEOUT or RC_PANIC; already logged
    }
}

/// Shutdown all plugins and free the engine.
///
/// `handle` stays `*mut` here because we consume the Box (this is the one
/// place we genuinely take exclusive ownership — destroying the
/// allocation). All other entry points use `*const`.
///
/// # Safety
/// `handle` must be a valid handle from `cpex_engine_new`. After this
/// call, the handle is invalid and must not be used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_shutdown(handle: *mut CpexEngineInner) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` is non-null and, per the caller contract, came from
    // `Box::into_raw` in a constructor and has not been freed.
    let inner = unsafe { Box::from_raw(handle) };
    // Wrap shutdown in catch_unwind + timeout so a misbehaving plugin
    // can't hang teardown forever or unwind across the FFI boundary.
    // We don't have a return value here — `inner` is dropped at function
    // end either way, freeing the engine and runtime.
    let _ = run_safely(inner.engine.shutdown(), "cpex_shutdown");
}

/// Check if any plugins are registered for a hook name.
///
/// Returns 1 (true) or 0 (false). No serialization — just a hash lookup.
///
/// # Safety
/// `handle` must be valid. `hook_name` must point to `hook_len` bytes of UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_has_hooks_for(
    handle: *const CpexEngineInner,
    hook_name: *const c_char,
    hook_len: c_int,
) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => return 0,
    };
    // SAFETY: the caller guarantees `hook_name` is NULL or points to `hook_len` readable bytes.
    let name = match unsafe { c_str_to_slice(hook_name, hook_len) } {
        Some(s) => s,
        None => return 0,
    };
    if inner.engine.has_hooks_for(name) {
        1
    } else {
        0
    }
}

/// Get the number of registered plugins.
///
/// No serialization — returns an integer directly.
///
/// # Safety
/// `handle` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_plugin_count(handle: *const CpexEngineInner) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    match unsafe { handle.as_ref() } {
        Some(m) => m.engine.plugin_count() as c_int,
        None => 0,
    }
}

/// Whether the engine has been initialized (i.e., `cpex_initialize`
/// returned successfully and `cpex_shutdown` has not been called).
///
/// Returns 1 if initialized, 0 otherwise (including null handle).
///
/// # Safety
/// `handle` must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_is_initialized(handle: *const CpexEngineInner) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    match unsafe { handle.as_ref() } {
        Some(m) if m.engine.is_initialized() => 1,
        _ => 0,
    }
}

/// Get the names of all registered plugins as MessagePack-encoded
/// `Vec<String>`. Caller must free the returned bytes with
/// `cpex_free_bytes`.
///
/// Returns an `RC_*` code; on success the names are written to
/// `*names_msgpack_out` / `*names_len_out`.
///
/// # Safety
/// `handle` must be valid. Output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_plugin_names(
    handle: *const CpexEngineInner,
    names_msgpack_out: *mut *mut u8,
    names_len_out: *mut c_int,
) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    let names = inner.engine.plugin_names();
    let bytes = match rmp_serde::to_vec_named(&names) {
        Ok(b) => b,
        Err(_) => return RC_SERIALIZE_ERROR,
    };
    let (ptr, len) = alloc_bytes(&bytes);
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *names_msgpack_out = ptr;
        *names_len_out = len;
    }
    RC_OK
}

/// Invoke a hook by name.
///
/// Payload and extensions are passed as MessagePack bytes.
///
/// A hook name removed in 0.3 (`tool_pre_invoke`, `identity_resolve` and
/// the rest of `cpex::host::REMOVED_HOOKS`) returns `RC_INVALID_INPUT` and
/// logs its replacement: it would reach no handler, so dispatching it would
/// allow with no policy evaluated. An `identity.resolve` call with a
/// `PAYLOAD_IDENTITY` payload that sets any resolver output field
/// (`subject`, `client`, `caller_workload`, `delegation`, `raw_credentials`,
/// `resolved_at`, `raw_claims`) also returns `RC_INVALID_INPUT`.
/// ContextTable is an opaque handle (NULL for first invocation).
/// Returns MessagePack-encoded PipelineResult + opaque handles for
/// context table and background tasks.
///
/// # Ownership contract
///
/// **The caller's input `context_table` is unconditionally consumed
/// by this function** — even on error paths (RC_INVALID_HANDLE,
/// RC_INVALID_INPUT, RC_PARSE_ERROR, RC_TIMEOUT, RC_PANIC, etc.).
/// The Box is freed inside `cpex_invoke`; the caller's pointer is
/// dead once this function returns. This mirrors the pattern used
/// by `cpex_wait_background` and lets the Go binding nil its handle
/// unconditionally after the call without leaking the underlying Box.
///
/// On `RC_OK`, a **fresh** `CpexContextTableInner` Box is allocated
/// and its raw pointer is written to `*context_table_out`. On any
/// non-OK return, `*context_table_out` is left as a null pointer
/// (initialized at function entry). The other out parameters
/// (`result_msgpack_out`, `result_len_out`, `bg_handle_out`) follow
/// the same discipline: null/zero on error, populated on success.
///
/// Previously the function consumed the input only after validation
/// passed but before `run_safely`. On `RC_TIMEOUT` / `RC_PANIC` the
/// input had been consumed but `*context_table_out` was never written,
/// so the Go wrapper kept its stale handle and a subsequent
/// `ContextTable.Close()` ran `cpex_release_context_table` on
/// already-freed memory.
///
/// # Safety
/// All pointer parameters must be valid or NULL where documented.
/// `handle` is `*const`: `PolicyEngine::invoke_by_name` takes `&self`
/// after the ArcSwap snapshot refactor. The previous `*mut` + `as_mut()`
/// shape produced aliased `&mut` references when two goroutines called
/// this concurrently — UB regardless of what the called code did. The
/// `&self` API plus `*const` here is sound for parallel dispatch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_invoke(
    handle: *const CpexEngineInner,
    hook_name: *const c_char,
    hook_len: c_int,
    payload_type: u8,
    payload_msgpack: *const u8,
    payload_len: c_int,
    extensions_msgpack: *const u8,
    extensions_len: c_int,
    context_table: *mut CpexContextTableInner, // NULL for first call
    result_msgpack_out: *mut *mut u8,
    result_len_out: *mut c_int,
    context_table_out: *mut *mut CpexContextTableInner,
    bg_handle_out: *mut *mut CpexBackgroundTasksInner,
) -> c_int {
    // Initialize all out params to safe defaults. Any early return
    // from here on leaves a consistent state for the caller: every
    // out pointer is null/zero, so a downstream attempt to dereference
    // produces a clean null-deref crash rather than reading uninit
    // stack memory. The success path overwrites these at the end.
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *result_msgpack_out = std::ptr::null_mut();
        *result_len_out = 0;
        *context_table_out = std::ptr::null_mut();
        *bg_handle_out = std::ptr::null_mut();
    }

    // Take ownership of the input context_table *immediately*, before
    // any validation that could return an error code. From this point
    // on, the caller's `context_table` pointer is dead — equivalent
    // to free'd memory from the caller's perspective. This mirrors
    // how `cpex_wait_background` handles `bg_handle`: ownership
    // transfers on entry, the caller nils its reference, and Rust
    // is responsible for the Box's lifetime from then on. Pre-fix,
    // consumption happened mid-function after some validations, which
    // meant validation errors left the input alive (one ownership
    // model) and post-validation errors left it consumed without
    // writing `*context_table_out` (a *different* ownership model).
    // Two contracts in one function is exactly what produced the
    // use-after-free.
    let input_ctx_table: Option<PluginContextTable> = if context_table.is_null() {
        None
    } else {
        // Box::from_raw consumes the allocation; it'll drop at the
        // end of this scope if not moved into Some(...). When moved
        // into Some(...), the table value lives until invoke_by_name
        // either uses it or it's dropped on a Future-cancellation
        // path (RC_TIMEOUT). Either way the Box is gone.
        // SAFETY: `context_table` is non-null and, per the caller contract,
        // a table handle from a prior invoke that has not been freed.
        let ct = unsafe { Box::from_raw(context_table) };
        Some(ct.table)
    };

    // Validate engine handle. `input_ctx_table` already owns the
    // input data — if we return here, it drops cleanly.
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    // SAFETY: the caller guarantees `hook_name` is NULL or points to `hook_len` readable bytes.
    let name = match unsafe { c_str_to_slice(hook_name, hook_len) } {
        Some(s) => s,
        None => return RC_INVALID_INPUT,
    };
    if let Err(rc) = reject_removed_hook(name, "cpex_invoke") {
        return rc;
    }

    // Deserialize payload using the type registry
    // SAFETY: the caller guarantees `payload_msgpack` is NULL or points to `payload_len` readable bytes.
    let payload_bytes = match unsafe { c_bytes_to_slice(payload_msgpack, payload_len) } {
        Some(b) => b,
        None => return RC_INVALID_INPUT,
    };

    let payload: Box<dyn PluginPayload> = match deserialize_payload(payload_type, payload_bytes) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("cpex_invoke: {}", e);
            return RC_PARSE_ERROR;
        },
    };
    if let Err(rc) = reject_resolved_identity_payload(name, payload.as_ref(), "cpex_invoke") {
        return rc;
    }

    // Deserialize extensions from MessagePack
    let extensions: Extensions = if extensions_len > 0 {
        // SAFETY: the caller guarantees `extensions_msgpack` is NULL or points to `extensions_len` readable bytes.
        let ext_bytes = match unsafe { c_bytes_to_slice(extensions_msgpack, extensions_len) } {
            Some(b) => b,
            None => return RC_INVALID_INPUT,
        };
        match rmp_serde::from_slice(ext_bytes) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("cpex_invoke: extensions deserialize failed: {}", e);
                return RC_PARSE_ERROR;
            },
        }
    } else {
        Extensions::default()
    };

    // Invoke the hook with wall-clock timeout + panic catch.
    let (mut result, bg) = match run_safely(
        inner
            .engine
            .invoke_by_name(name, payload, extensions, input_ctx_table),
        "cpex_invoke",
    ) {
        SafeRun::Ok(r) => r,
        // *context_table_out is already null (set at function entry);
        // the input table has been consumed by invoke_by_name's call
        // frame and dropped. Caller's handle is dead, no replacement.
        other => return other.rc(), // RC_TIMEOUT or RC_PANIC; already logged
    };

    // Serialize modified payload using the type registry. A failure
    // here is partial — the rest of the result (continue_processing,
    // violation, metadata, modified_extensions) is still valid — so
    // we surface the issue as a synthetic FFI-layer record in
    // `result.errors` rather than failing the whole call. This is
    // uniform with how the pipeline reports plugin-level errors
    // swallowed by `on_error: ignore` / `on_error: disable`.
    let (result_payload_type, modified_payload_bytes) = match result.modified_payload.as_ref() {
        None => (payload_type, None),
        Some(p) => match serialize_payload(p.as_ref()) {
            Ok((t, b)) => (t, Some(b)),
            Err(e) => {
                tracing::warn!("cpex_invoke: dropped modified payload — {}", e);
                result
                    .errors
                    .push(praxis_policy_core::error::PluginErrorRecord {
                        plugin_name: "<ffi>".to_string(),
                        message: format!(
                            "modified payload could not be serialized across FFI: {e}"
                        ),
                        code: Some("ffi_serialize_error".to_string()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    });
                (payload_type, None)
            },
        },
    };

    // Serialize modified extensions if present
    let modified_extensions_bytes: Option<Vec<u8>> = result
        .modified_extensions
        .as_ref()
        .and_then(|ext| rmp_serde::to_vec_named(ext).ok());

    // Build FFI result. `errors` flows through verbatim — it's already
    // PluginErrorRecord which is the canonical wire shape.
    let ffi_result = FfiPipelineResult {
        continue_processing: result.continue_processing,
        violation: result.violation,
        errors: result.errors,
        metadata: result.metadata,
        payload_type: result_payload_type,
        modified_payload: modified_payload_bytes,
        payload_modified: result.payload_modified,
        modified_extensions: modified_extensions_bytes,
    };

    let result_bytes = match rmp_serde::to_vec_named(&ffi_result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("cpex_invoke: result serialize failed: {}", e);
            return RC_SERIALIZE_ERROR;
        },
    };

    let (ptr, len) = alloc_bytes(&result_bytes);
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *result_msgpack_out = ptr;
        *result_len_out = len;

        *context_table_out = Box::into_raw(Box::new(CpexContextTableInner {
            table: result.context_table,
        }));

        *bg_handle_out = Box::into_raw(Box::new(CpexBackgroundTasksInner { tasks: bg }));
    }

    RC_OK
}

/// Fused `identity.resolve` + hook invoke.
///
/// Runs `identity.resolve` and the named hook in ONE FFI call so the
/// resolved `Extensions` — including `raw_credentials`, whose inbound
/// tokens are `#[serde(skip)]` + `Zeroizing` and therefore cannot survive
/// an FFI round-trip — flow from identity into the hook entirely in Rust
/// memory. This is the FFI analogue of an in-process host calling
/// `IdentityPayload::apply_to_extensions(...)` between hooks; it lets
/// out-of-process hosts (Go / Python / WASM) drive `delegate()` flows
/// that need the inbound bearer token, which a two-call
/// resolve-then-invoke sequence loses on the way back out.
///
/// `identity_msgpack` is a `PAYLOAD_IDENTITY`-shaped `IdentityPayload`
/// carrying request headers. When `identity_len <= 0` or no
/// `identity.resolve` hook is registered, this degrades to a plain hook
/// invoke against the supplied extensions. If `identity.resolve` denies
/// (e.g. bad token), that denial is returned and the hook does not run.
/// An identity payload that sets any resolver output field, or a removed
/// hook name, returns `RC_INVALID_INPUT` as in [`cpex_invoke`].
///
/// # Safety / ownership
/// Identical contract to [`cpex_invoke`]: the input `context_table` is
/// consumed unconditionally (used for the hook invoke; the internal
/// identity invoke gets a fresh one); out params are null/zero on error
/// and populated on `RC_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_invoke_resolved(
    handle: *const CpexEngineInner,
    identity_msgpack: *const u8,
    identity_len: c_int,
    hook_name: *const c_char,
    hook_len: c_int,
    payload_type: u8,
    payload_msgpack: *const u8,
    payload_len: c_int,
    extensions_msgpack: *const u8,
    extensions_len: c_int,
    context_table: *mut CpexContextTableInner, // NULL for first call
    result_msgpack_out: *mut *mut u8,
    result_len_out: *mut c_int,
    context_table_out: *mut *mut CpexContextTableInner,
    bg_handle_out: *mut *mut CpexBackgroundTasksInner,
) -> c_int {
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *result_msgpack_out = std::ptr::null_mut();
        *result_len_out = 0;
        *context_table_out = std::ptr::null_mut();
        *bg_handle_out = std::ptr::null_mut();
    }

    // Consume the input context table up front (used for the hook invoke),
    // matching cpex_invoke's unconditional-consume ownership contract.
    let input_ctx_table: Option<PluginContextTable> = if context_table.is_null() {
        None
    } else {
        // SAFETY: `context_table` is non-null and, per the caller contract,
        // a table handle from a prior invoke that has not been freed.
        Some(unsafe { Box::from_raw(context_table) }.table)
    };

    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    // SAFETY: the caller guarantees `hook_name` is NULL or points to `hook_len` readable bytes.
    let name = match unsafe { c_str_to_slice(hook_name, hook_len) } {
        Some(s) => s,
        None => return RC_INVALID_INPUT,
    };
    if let Err(rc) = reject_removed_hook(name, "cpex_invoke_resolved") {
        return rc;
    }

    // SAFETY: the caller guarantees `payload_msgpack` is NULL or points to `payload_len` readable bytes.
    let payload_bytes = match unsafe { c_bytes_to_slice(payload_msgpack, payload_len) } {
        Some(b) => b,
        None => return RC_INVALID_INPUT,
    };
    let payload: Box<dyn PluginPayload> = match deserialize_payload(payload_type, payload_bytes) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("cpex_invoke_resolved: {}", e);
            return RC_PARSE_ERROR;
        },
    };
    if let Err(rc) =
        reject_resolved_identity_payload(name, payload.as_ref(), "cpex_invoke_resolved")
    {
        return rc;
    }

    let base_extensions: Extensions = if extensions_len > 0 {
        // SAFETY: the caller guarantees `extensions_msgpack` is NULL or points to `extensions_len` readable bytes.
        let ext_bytes = match unsafe { c_bytes_to_slice(extensions_msgpack, extensions_len) } {
            Some(b) => b,
            None => return RC_INVALID_INPUT,
        };
        match rmp_serde::from_slice(ext_bytes) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("cpex_invoke_resolved: extensions deserialize failed: {}", e);
                return RC_PARSE_ERROR;
            },
        }
    } else {
        Extensions::default()
    };

    // Identity resolution (in-process): resolve identity and merge the
    // result into the extensions BEFORE the hook runs, so raw_credentials
    // (skip-serialized across FFI) reach the hook in Rust memory. Skipped
    // when no identity payload was supplied or no identity.resolve hook is
    // registered.
    let merged_extensions: Extensions = if identity_len > 0
        && inner
            .engine
            .has_hooks_for(praxis_policy_core::identity::HOOK_IDENTITY_RESOLVE)
    {
        // SAFETY: the caller guarantees `identity_msgpack` is NULL or points to `identity_len` readable bytes.
        let id_bytes = match unsafe { c_bytes_to_slice(identity_msgpack, identity_len) } {
            Some(b) => b,
            None => return RC_INVALID_INPUT,
        };
        let id_payload: IdentityPayload = match rmp_serde::from_slice(id_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    "cpex_invoke_resolved: identity payload deserialize failed: {}",
                    e
                );
                return RC_PARSE_ERROR;
            },
        };
        if let Err(rc) = reject_resolved_identity(&id_payload, "cpex_invoke_resolved/identity") {
            return rc;
        }

        // The identity hook gets the caller's extensions so its `meta`
        // selects the route: under `dispatch: policy` the route's
        // `authentication:` list decides which resolvers run, and a
        // request with no route meta is refused as unidentified.
        let (id_result, _id_bg) = match run_safely(
            inner.engine.invoke_by_name(
                praxis_policy_core::identity::HOOK_IDENTITY_RESOLVE,
                Box::new(id_payload),
                base_extensions.clone(),
                None,
            ),
            "cpex_invoke_resolved/identity",
        ) {
            SafeRun::Ok(r) => r,
            other => return other.rc(),
        };

        // Identity denied (bad / missing credential): surface that denial
        // as the result; the hook never runs. Identity resolvers (jwt,
        // mtls) are synchronous and don't spawn background tasks, so the
        // identity bg is dropped.
        if !id_result.continue_processing {
            // SAFETY: the out pointers are forwarded from this function's
            // caller, who guarantees they are writable.
            return unsafe {
                finish_pipeline_result(
                    id_result,
                    None,
                    payload_type,
                    result_msgpack_out,
                    result_len_out,
                    context_table_out,
                    bg_handle_out,
                )
            };
        }

        match IdentityPayload::from_pipeline_result(&id_result) {
            Some(resolved) => resolved.apply_to_extensions(base_extensions),
            None => base_extensions,
        }
    } else {
        base_extensions
    };

    let (result, bg) = match run_safely(
        inner
            .engine
            .invoke_by_name(name, payload, merged_extensions, input_ctx_table),
        "cpex_invoke_resolved",
    ) {
        SafeRun::Ok(r) => r,
        other => return other.rc(),
    };

    // SAFETY: the out pointers are forwarded from this function's caller,
    // who guarantees they are writable.
    unsafe {
        finish_pipeline_result(
            result,
            Some(bg),
            payload_type,
            result_msgpack_out,
            result_len_out,
            context_table_out,
            bg_handle_out,
        )
    }
}

/// Serialize a `(PipelineResult, Option<BackgroundTasks>)` into the FFI
/// out-params. Shared tail for [`cpex_invoke_resolved`]'s hook-result and
/// identity-denial paths; mirrors [`cpex_invoke`]'s inline serialization.
/// `bg` is `None` on the identity-denial path (no hook background tasks to
/// hand back) — `*bg_handle_out` is then left null.
///
/// # Safety
/// Out pointers must be writable. Returns `RC_OK` on success or
/// `RC_SERIALIZE_ERROR` if the result can't be MessagePack-encoded.
unsafe fn finish_pipeline_result(
    mut result: praxis_policy_core::executor::PipelineResult,
    bg: Option<BackgroundTasks>,
    payload_type: u8,
    result_msgpack_out: *mut *mut u8,
    result_len_out: *mut c_int,
    context_table_out: *mut *mut CpexContextTableInner,
    bg_handle_out: *mut *mut CpexBackgroundTasksInner,
) -> c_int {
    let (result_payload_type, modified_payload_bytes) = match result.modified_payload.as_ref() {
        None => (payload_type, None),
        Some(p) => match serialize_payload(p.as_ref()) {
            Ok((t, b)) => (t, Some(b)),
            Err(e) => {
                tracing::warn!("cpex_invoke_resolved: dropped modified payload — {}", e);
                result
                    .errors
                    .push(praxis_policy_core::error::PluginErrorRecord {
                        plugin_name: "<ffi>".to_string(),
                        message: format!(
                            "modified payload could not be serialized across FFI: {e}"
                        ),
                        code: Some("ffi_serialize_error".to_string()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    });
                (payload_type, None)
            },
        },
    };

    let modified_extensions_bytes: Option<Vec<u8>> = result
        .modified_extensions
        .as_ref()
        .and_then(|ext| rmp_serde::to_vec_named(ext).ok());

    let ffi_result = FfiPipelineResult {
        continue_processing: result.continue_processing,
        violation: result.violation,
        errors: result.errors,
        metadata: result.metadata,
        payload_type: result_payload_type,
        modified_payload: modified_payload_bytes,
        payload_modified: result.payload_modified,
        modified_extensions: modified_extensions_bytes,
    };

    let result_bytes = match rmp_serde::to_vec_named(&ffi_result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("cpex_invoke_resolved: result serialize failed: {}", e);
            return RC_SERIALIZE_ERROR;
        },
    };

    let (ptr, len) = alloc_bytes(&result_bytes);
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *result_msgpack_out = ptr;
        *result_len_out = len;

        *context_table_out = Box::into_raw(Box::new(CpexContextTableInner {
            table: result.context_table,
        }));

        *bg_handle_out = match bg {
            Some(b) => Box::into_raw(Box::new(CpexBackgroundTasksInner { tasks: b })),
            None => std::ptr::null_mut(),
        };
    }

    RC_OK
}

/// Wait for all background tasks to complete.
///
/// Returns MessagePack-encoded errors (empty array if none).
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `bg_handle` must be a valid handle from `cpex_invoke`.
/// After this call, the handle is consumed and invalid.
/// `handle` is `*const`: only the runtime is borrowed (`&self`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_wait_background(
    handle: *const CpexEngineInner,
    bg_handle: *mut CpexBackgroundTasksInner,
    errors_msgpack_out: *mut *mut u8,
    errors_len_out: *mut c_int,
) -> c_int {
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(m) => m,
        None => {
            // Consume `bg_handle` even on the failure path — the Go
            // caller has already nil'd its reference, so without
            // dropping the Box here we'd leak the BackgroundTasks
            // allocation (and its still-running task handles).
            if !bg_handle.is_null() {
                // SAFETY: `bg_handle` is non-null and, per the caller
                // contract, a live handle from `cpex_invoke`.
                drop(unsafe { Box::from_raw(bg_handle) });
            }
            return RC_INVALID_HANDLE;
        },
    };

    if bg_handle.is_null() {
        let empty: Vec<praxis_policy_core::error::PluginErrorRecord> = Vec::new();
        let empty_bytes = match rmp_serde::to_vec_named(&empty) {
            Ok(b) => b,
            Err(_) => return RC_SERIALIZE_ERROR,
        };
        let (ptr, len) = alloc_bytes(&empty_bytes);
        // SAFETY: the caller guarantees the output pointers are writable.
        unsafe {
            *errors_msgpack_out = ptr;
            *errors_len_out = len;
        }
        return RC_OK;
    }

    // SAFETY: `bg_handle` is non-null (checked above) and, per the caller
    // contract, a live handle from `cpex_invoke`.
    let bg = unsafe { Box::from_raw(bg_handle) };
    // `inner` is now unused but the borrow proved the engine is alive
    // for the duration of this call (the read lock on the Go side).
    let _ = inner;
    let errors = match run_safely(bg.tasks.wait_for_background_tasks(), "cpex_wait_background") {
        SafeRun::Ok(errs) => errs,
        other => return other.rc(), // RC_TIMEOUT or RC_PANIC; already logged
    };

    // Flatten each Rust PluginError variant into the canonical wire
    // shape so Go callers get structured fields (plugin_name, code,
    // details) instead of a stringified Display impl.
    let ffi_errors: Vec<praxis_policy_core::error::PluginErrorRecord> = errors
        .iter()
        .map(praxis_policy_core::error::PluginErrorRecord::from)
        .collect();
    let error_bytes = match rmp_serde::to_vec_named(&ffi_errors) {
        Ok(b) => b,
        Err(_) => return RC_SERIALIZE_ERROR,
    };

    let (ptr, len) = alloc_bytes(&error_bytes);
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *errors_msgpack_out = ptr;
        *errors_len_out = len;
    }

    RC_OK
}

/// Free a background tasks handle without waiting.
///
/// Tasks continue running in the tokio runtime.
///
/// # Safety
/// `bg_handle` must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_free_background(bg_handle: *mut CpexBackgroundTasksInner) {
    if !bg_handle.is_null() {
        // SAFETY: `bg_handle` is non-null and, per the caller contract, a
        // live handle from `cpex_invoke`.
        drop(unsafe { Box::from_raw(bg_handle) });
    }
}

/// Free a context table handle.
///
/// # Safety
/// `ct` must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_free_context_table(ct: *mut CpexContextTableInner) {
    if !ct.is_null() {
        // SAFETY: `ct` is non-null and, per the caller contract, a live
        // context table handle from `cpex_invoke`.
        drop(unsafe { Box::from_raw(ct) });
    }
}

/// Free a byte buffer allocated by the FFI layer.
///
/// # Safety
/// `ptr` must have been allocated by this library (from `cpex_invoke`
/// or `cpex_wait_background`). `len` must match the original allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_free_bytes(ptr: *mut u8, len: c_int) {
    if ptr.is_null() || len <= 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(len as usize, 1)
        .expect("align 1 is always valid and len (a positive c_int) is far under isize::MAX");
    // SAFETY: per the caller contract, `ptr` came from `alloc_bytes` with
    // this same `len` and alignment 1, and has not been freed.
    unsafe { std::alloc::dealloc(ptr, layout) };
}

/// Pipeline result serialized across the FFI boundary.
/// Matches the Go `PipelineResult` struct field names.
///
/// `errors` carries records from `on_error: ignore` / `on_error: disable`
/// plugins so the Go caller can surface them programmatically rather
/// than parsing log output. Fire-and-forget errors come through
/// `BackgroundTasks::wait_for_background_tasks()` instead.
#[derive(serde::Serialize, serde::Deserialize)]
struct FfiPipelineResult {
    continue_processing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    violation: Option<praxis_policy_core::error::PluginViolation>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    errors: Vec<praxis_policy_core::error::PluginErrorRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    /// Payload type ID — tells the Go caller how to deserialize.
    payload_type: u8,
    /// Modified payload as raw MessagePack bytes. Present on every
    /// allowed pipeline, carrying the final payload whether or not a
    /// plugin touched it — read `payload_modified` to learn whether
    /// anything actually changed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(with = "serde_bytes_opt")]
    modified_payload: Option<Vec<u8>>,
    /// Whether a plugin's payload modification was accepted. The exact
    /// signal; `modified_payload.is_some()` is not a substitute, and
    /// comparing payload contents across the boundary cannot see
    /// mutations to non-text parts.
    #[serde(default)]
    payload_modified: bool,
    /// Modified extensions as raw MessagePack bytes (if a plugin modified them).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(with = "serde_bytes_opt")]
    modified_extensions: Option<Vec<u8>>,
}

/// Helper for serializing `Option<Vec<u8>>` as binary in MessagePack.
mod serde_bytes_opt {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => serde::Serialize::serialize(&serde_bytes::Bytes::new(bytes), s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        use serde::Deserialize;
        Option::<serde_bytes::ByteBuf>::deserialize(d).map(|o| o.map(|b| b.into_vec()))
    }
}

/// A generic payload that wraps a deserialized serde_json::Value.
///
/// Used for FFI dispatch when the concrete payload type isn't known
/// at compile time. The value was deserialized from MessagePack on
/// the Go side and will be passed to Rust plugins as-is.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericPayload {
    pub value: serde_json::Value,
}

praxis_policy_core::impl_plugin_payload!(GenericPayload);

// These tests call the `extern "C"` functions directly from Rust to
// exercise the FFI safety layer (catch_unwind, return-code mapping,
// payload-type validation) without needing a Go test harness. The
// reviewer flagged that `cpex-ffi` had zero `#[cfg(test)]` coverage —
// this seeds the file with regressions for the highest-value invariants.
#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use praxis_policy_core::hooks::PluginResult;
    use praxis_policy_core::hooks::payload::Extensions;
    use praxis_policy_core::hooks::trait_def::HookTypeDef;
    use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};

    /// Test hook type using GenericPayload — that's the type
    /// PAYLOAD_GENERIC produces at the FFI deserialization boundary,
    /// so the typed-adapter downcast actually finds the handler.
    /// (Defining a custom TestPayload would mean the executor's
    /// downcast finds None and the handler never runs.)
    struct TestHook;
    impl HookTypeDef for TestHook {
        type Payload = GenericPayload;
        type Result = PluginResult<GenericPayload>;
        const NAME: &'static str = "test_hook";
    }

    /// A plugin whose handler always panics — exercises the `catch_unwind`
    /// path inside `run_safely`.
    struct PanickingPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for PanickingPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl praxis_policy_core::hooks::HookHandler<TestHook> for PanickingPlugin {
        async fn handle(
            &self,
            _payload: &GenericPayload,
            _extensions: &Extensions,
            _ctx: &mut praxis_policy_core::context::PluginContext,
        ) -> PluginResult<GenericPayload> {
            panic!("simulated panic from PanickingPlugin");
        }
    }

    /// Build an FFI-shaped engine for testing. Bypasses
    /// `cpex_engine_new` so we can register Rust plugins directly via
    /// the engine's typed API.
    fn build_test_engine() -> *mut CpexEngineInner {
        // Touch the shared runtime so it's initialized; tests use it
        // rather than a per-engine runtime.
        let _ = shared_runtime();
        let engine = Arc::new(praxis_policy_core::engine::PolicyEngine::default());
        Box::into_raw(Box::new(CpexEngineInner::new(engine)))
    }

    fn register_panicking_plugin(handle: &CpexEngineInner) {
        let cfg = PluginConfig {
            name: "panicker".into(),
            kind: "test".into(),
            hooks: vec!["test_hook".into()],
            mode: PluginMode::Sequential,
            ..Default::default()
        };
        let plugin = Arc::new(PanickingPlugin { cfg: cfg.clone() });
        handle
            .engine
            .register_handler::<TestHook, _>(plugin, cfg)
            .expect("register");
    }

    /// Encode a generic JSON value to MessagePack, the wire format
    /// PAYLOAD_GENERIC consumes. Returns bytes the FFI can borrow.
    fn payload_bytes(value: &str) -> Vec<u8> {
        rmp_serde::to_vec_named(&serde_json::json!({ "value": value })).expect("encode payload")
    }

    /// Drive cpex_invoke with a single hook name and the given payload.
    /// Returns the raw rc; output buffers are dropped.
    unsafe fn invoke_for_test(
        handle: *const CpexEngineInner,
        payload_type: u8,
        payload: &[u8],
    ) -> c_int {
        // SAFETY: forwarded caller contract; `handle` is live or NULL.
        unsafe { invoke_and_decode(handle, payload_type, payload).0 }
    }

    /// Like `invoke_for_test`, also returning the decoded result on
    /// `RC_OK`.
    unsafe fn invoke_and_decode(
        handle: *const CpexEngineInner,
        payload_type: u8,
        payload: &[u8],
    ) -> (c_int, Option<FfiPipelineResult>) {
        let hook_name = b"test_hook";
        let mut result_ptr: *mut u8 = ptr::null_mut();
        let mut result_len: c_int = 0;
        let mut ct_out: *mut CpexContextTableInner = ptr::null_mut();
        let mut bg_out: *mut CpexBackgroundTasksInner = ptr::null_mut();

        // SAFETY: `handle` is live or NULL per the caller contract; the
        // input slices are borrowed for the call and the out pointers are
        // locals.
        let rc = unsafe {
            cpex_invoke(
                handle,
                hook_name.as_ptr() as *const c_char,
                hook_name.len() as c_int,
                payload_type,
                payload.as_ptr(),
                payload.len() as c_int,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut result_ptr,
                &mut result_len,
                &mut ct_out,
                &mut bg_out,
            )
        };

        // Drain any output buffers / handles to avoid leaks across tests.
        let mut decoded = None;
        // SAFETY: every non-null out value was just written by
        // `cpex_invoke` and is freed exactly once here.
        unsafe {
            if !result_ptr.is_null() {
                let bytes = std::slice::from_raw_parts(result_ptr, result_len as usize);
                decoded = Some(rmp_serde::from_slice(bytes).expect("decode FFI result"));
                cpex_free_bytes(result_ptr, result_len);
            }
            if !ct_out.is_null() {
                cpex_free_context_table(ct_out);
            }
            if !bg_out.is_null() {
                cpex_free_background(bg_out);
            }
        }
        (rc, decoded)
    }

    /// A panicking plugin must never unwind across `extern "C"`. PPE
    /// contains the panic in its executor and reports it as a failed
    /// pipeline, so the FFI returns a structured result rather than
    /// `RC_PANIC`; `run_safely` stays as the backstop for a panic in the
    /// engine itself.
    #[test]
    fn cpex_invoke_contains_a_plugin_panic() {
        let handle = build_test_engine();
        // Defer cleanup so a test failure doesn't leak the engine.
        struct EngineGuard(*mut CpexEngineInner);
        impl Drop for EngineGuard {
            fn drop(&mut self) {
                unsafe {
                    cpex_shutdown(self.0);
                }
            }
        }
        let _guard = EngineGuard(handle);

        unsafe {
            let inner = &*handle;
            register_panicking_plugin(inner);
            // Engine must be initialized for the pipeline to dispatch.
            let init_rc = cpex_initialize(handle);
            assert_eq!(init_rc, RC_OK, "init should succeed");

            let bytes = payload_bytes("trigger");
            let (rc, result) = invoke_and_decode(handle, PAYLOAD_GENERIC, &bytes);
            assert_eq!(rc, RC_OK, "the engine contains the panic");
            let result = result.expect("a decodable result");
            assert!(!result.continue_processing);
            let violation = result.violation.expect("the panic is reported");
            assert_eq!(violation.code, "plugin_panic");
        }
    }

    /// Invoking with an unknown `payload_type` must return
    /// `RC_PARSE_ERROR` — the deserialize_payload registry rejects
    /// unknown discriminators with a typed error code rather than a
    /// generic failure.
    #[test]
    fn cpex_invoke_returns_rc_parse_error_on_unknown_payload_type() {
        let handle = build_test_engine();
        struct EngineGuard(*mut CpexEngineInner);
        impl Drop for EngineGuard {
            fn drop(&mut self) {
                unsafe {
                    cpex_shutdown(self.0);
                }
            }
        }
        let _guard = EngineGuard(handle);

        unsafe {
            let inner = &*handle;
            register_panicking_plugin(inner); // need *some* plugin so dispatch runs
            assert_eq!(cpex_initialize(handle), RC_OK);

            // Unknown payload type — dispatch never reaches the plugin.
            let bytes = payload_bytes("trigger");
            let rc = invoke_for_test(handle, 99 /* not in registry */, &bytes);
            assert_eq!(
                rc, RC_PARSE_ERROR,
                "unknown payload_type should map to RC_PARSE_ERROR, got {}",
                rc,
            );
        }
    }

    /// `parse_worker_threads` turns a CPEX_FFI_WORKER_THREADS value into
    /// a positive count, returning None for zero / negative /
    /// unparseable. It takes the raw string so the test never mutates
    /// the process environment, which would race other test threads.
    #[test]
    fn parse_worker_threads_parses_correctly() {
        assert_eq!(parse_worker_threads("8"), Some(8));
        assert_eq!(parse_worker_threads("0"), None, "zero should fall back");
        assert_eq!(
            parse_worker_threads("-3"),
            None,
            "negative should fall back"
        );
        assert_eq!(
            parse_worker_threads("garbage"),
            None,
            "unparseable should fall back"
        );
    }

    /// `cpex_configure_runtime` rejects non-positive worker counts
    /// before touching the shared runtime — the early bounds check
    /// fires regardless of OnceLock state, so this is order-independent.
    #[test]
    fn cpex_configure_runtime_rejects_non_positive_workers() {
        assert_eq!(cpex_configure_runtime(0), RC_INVALID_INPUT);
        assert_eq!(cpex_configure_runtime(-1), RC_INVALID_INPUT);
    }

    /// Once the shared runtime is initialized (e.g., by any prior test
    /// or `cpex_engine_new` call), subsequent configure attempts must
    /// fail with `RC_INVALID_INPUT` — the runtime is single-init.
    #[test]
    fn cpex_configure_runtime_after_init_returns_invalid_input() {
        // Touch the runtime to ensure it's initialized. This may already
        // have happened in another test; either way OnceLock is set.
        let _ = shared_runtime();
        // Configure should now refuse: window has closed.
        assert_eq!(cpex_configure_runtime(2), RC_INVALID_INPUT);
    }

    /// `serialize_payload` returns `Ok` for known registered types so
    /// modifications round-trip cleanly.
    #[test]
    fn serialize_payload_round_trips_generic() {
        let gp = GenericPayload {
            value: serde_json::json!({ "k": "v" }),
        };
        let (t, bytes) = serialize_payload(&gp).expect("known type should serialize");
        assert_eq!(t, PAYLOAD_GENERIC);
        // Confirm the encoded bytes deserialize back to the same shape
        // — guards against silent type-id/wire-format drift.
        let value: serde_json::Value = rmp_serde::from_slice(&bytes).expect("round-trip decode");
        assert_eq!(value, serde_json::json!({ "k": "v" }));
    }

    /// An identity result keeps its input and resolved fields but drops the
    /// request `headers`, which carry the inbound credential.
    #[test]
    fn serialize_payload_drops_identity_headers() {
        let idp: IdentityPayload = serde_json::from_value(serde_json::json!({
            "source": "bearer",
            "source_header": "authorization",
            "headers": {"authorization": "Bearer secret-token", "x-trace": "t1"},
            "client_host": "10.0.0.1",
            "client_port": 443,
            "subject": {"id": "alice"},
            "raw_claims": {"sub": "alice"},
        }))
        .unwrap();
        let (t, bytes) = serialize_payload(&idp).expect("identity should serialize");
        assert_eq!(t, PAYLOAD_IDENTITY);
        let value: serde_json::Value = rmp_serde::from_slice(&bytes).expect("round-trip decode");
        assert!(value.get("headers").is_none(), "{value}");
        assert!(!value.to_string().contains("secret-token"), "{value}");
        assert_eq!(value["source"], "bearer");
        assert_eq!(value["source_header"], "authorization");
        assert_eq!(value["client_host"], "10.0.0.1");
        assert_eq!(value["client_port"], 443);
        assert_eq!(value["subject"]["id"], "alice");
        assert_eq!(value["raw_claims"]["sub"], "alice");
        // The bytes still decode as an identity payload on the other side.
        let back: IdentityPayload = rmp_serde::from_slice(&bytes).expect("decode as identity");
        assert!(back.subject.is_some());
    }

    /// `serialize_payload` returns `Err` for payload types the FFI
    /// registry doesn't know about. Without this contract the FFI
    /// silently dropped a plugin's modification — the caller saw
    /// `modified_payload = None` even though one was produced.
    /// This test pins the new error contract so that regression can't
    /// reappear.
    #[test]
    fn serialize_payload_returns_err_for_unknown_type() {
        // A custom PluginPayload impl that's not in the FFI registry —
        // simulates a plugin returning a custom payload type the
        // serializer doesn't know how to ship across the wire.
        #[derive(Clone)]
        struct CustomPayload;
        impl PluginPayload for CustomPayload {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }
            fn clone_boxed(&self) -> Box<dyn PluginPayload> {
                Box::new(self.clone())
            }
        }
        let err = serialize_payload(&CustomPayload).expect_err("unknown type should err");
        assert!(
            err.contains("unknown payload type"),
            "error message should identify the failure mode, got: {err}",
        );
    }

    /// A null engine handle must return `RC_INVALID_HANDLE` from
    /// every entry point — guards the `as_ref()` precondition.
    #[test]
    fn cpex_invoke_returns_rc_invalid_handle_on_null_mgr() {
        unsafe {
            let bytes = payload_bytes("x");
            let rc = invoke_for_test(ptr::null(), PAYLOAD_GENERIC, &bytes);
            assert_eq!(rc, RC_INVALID_HANDLE);

            assert_eq!(cpex_initialize(ptr::null()), RC_INVALID_HANDLE);
            assert_eq!(cpex_is_initialized(ptr::null()), 0);
        }
    }

    #[test]
    fn cpex_ffi_abi_version_is_3() {
        assert_eq!(cpex_ffi_abi_version(), 3);
        assert_eq!(FFI_ABI_VERSION, 3);
    }

    #[test]
    fn cpex_apl_install_rejects_null_handle() {
        unsafe {
            assert_eq!(cpex_apl_install(ptr::null(), 0), RC_INVALID_HANDLE);
        }
    }

    #[test]
    fn cpex_apl_install_rejects_unknown_flag_bits() {
        let handle = cpex_engine_new_default();
        unsafe {
            assert_eq!(cpex_apl_install(handle, 1 << 31), RC_INVALID_INPUT);
            // A rejected call installs nothing, so a valid one still runs.
            assert_eq!(cpex_apl_install(handle, 0), RC_OK);
            cpex_shutdown(handle);
        }
    }

    /// `cpex_invoke` on `hook` with no context table; frees every output
    /// and returns the rc.
    unsafe fn invoke_named(
        handle: *const CpexEngineInner,
        hook: &str,
        payload_type: u8,
        payload: &[u8],
    ) -> c_int {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: c_int = 0;
        let mut ct: *mut CpexContextTableInner = ptr::null_mut();
        let mut bg: *mut CpexBackgroundTasksInner = ptr::null_mut();
        // SAFETY: `handle` is live per the caller contract; inputs are
        // borrowed for the call and the out pointers are locals, each
        // freed once below.
        unsafe {
            let rc = cpex_invoke(
                handle,
                hook.as_ptr() as *const c_char,
                hook.len() as c_int,
                payload_type,
                payload.as_ptr(),
                payload.len() as c_int,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut out,
                &mut out_len,
                &mut ct,
                &mut bg,
            );
            free_outputs(out, out_len, ct, bg);
            rc
        }
    }

    /// `cpex_invoke_resolved` with an identity payload; frees every
    /// output and returns the rc.
    unsafe fn invoke_resolved_named(
        handle: *const CpexEngineInner,
        identity: &[u8],
        hook: &str,
        payload_type: u8,
        payload: &[u8],
    ) -> c_int {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: c_int = 0;
        let mut ct: *mut CpexContextTableInner = ptr::null_mut();
        let mut bg: *mut CpexBackgroundTasksInner = ptr::null_mut();
        // SAFETY: as in `invoke_named`.
        unsafe {
            let rc = cpex_invoke_resolved(
                handle,
                identity.as_ptr(),
                identity.len() as c_int,
                hook.as_ptr() as *const c_char,
                hook.len() as c_int,
                payload_type,
                payload.as_ptr(),
                payload.len() as c_int,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut out,
                &mut out_len,
                &mut ct,
                &mut bg,
            );
            free_outputs(out, out_len, ct, bg);
            rc
        }
    }

    unsafe fn free_outputs(
        out: *mut u8,
        out_len: c_int,
        ct: *mut CpexContextTableInner,
        bg: *mut CpexBackgroundTasksInner,
    ) {
        // SAFETY: each non-null value was written by an invoke and is
        // freed exactly once here.
        unsafe {
            if !out.is_null() {
                cpex_free_bytes(out, out_len);
            }
            if !ct.is_null() {
                cpex_free_context_table(ct);
            }
            if !bg.is_null() {
                cpex_free_background(bg);
            }
        }
    }

    fn identity_bytes(value: serde_json::Value) -> Vec<u8> {
        rmp_serde::to_vec_named(&value).expect("encode identity payload")
    }

    /// A removed hook name is refused at invoke time instead of
    /// dispatching to nothing and allowing.
    #[test]
    fn invoke_rejects_removed_hook_names() {
        let handle = build_test_engine();
        let payload = payload_bytes("x");
        unsafe {
            for (removed, _) in cpex::host::REMOVED_HOOKS {
                assert_eq!(
                    invoke_named(handle, removed, PAYLOAD_GENERIC, &payload),
                    RC_INVALID_INPUT,
                    "{removed}"
                );
                assert_eq!(
                    invoke_resolved_named(handle, &[], removed, PAYLOAD_GENERIC, &payload),
                    RC_INVALID_INPUT,
                    "{removed}"
                );
            }
            // A current name with no handler still dispatches and allows.
            assert_eq!(
                invoke_named(handle, "cmf.tool_pre_invoke", PAYLOAD_GENERIC, &payload),
                RC_OK
            );
            assert_eq!(
                invoke_named(handle, "custom.hook", PAYLOAD_GENERIC, &payload),
                RC_OK
            );
            cpex_shutdown(handle);
        }
    }

    /// An `identity.resolve` input carrying resolver output is refused on
    /// both invoke entry points; a plain input is accepted.
    #[test]
    fn invoke_rejects_identity_input_with_resolved_fields() {
        let input = identity_bytes(serde_json::json!({
            "source": "bearer",
            "headers": {"authorization": "Bearer x"},
        }));
        let forged = identity_bytes(serde_json::json!({
            "source": "bearer",
            "headers": {"authorization": "Bearer x"},
            "subject": {"id": "alice"},
        }));
        let generic = payload_bytes("x");
        unsafe {
            let handle = cpex_engine_new_default();
            assert_eq!(cpex_apl_install(handle, 0), RC_OK);
            // A registered identity.resolve handler, so the fused path
            // reads its identity payload.
            assert_eq!(load(handle, APL_YAML), RC_OK);

            assert_eq!(
                invoke_named(handle, "identity.resolve", PAYLOAD_IDENTITY, &forged),
                RC_INVALID_INPUT
            );
            assert_eq!(
                invoke_resolved_named(
                    handle,
                    &forged,
                    "cmf.tool_pre_invoke",
                    PAYLOAD_GENERIC,
                    &generic
                ),
                RC_INVALID_INPUT
            );
            assert_eq!(
                invoke_resolved_named(handle, &[], "identity.resolve", PAYLOAD_IDENTITY, &forged),
                RC_INVALID_INPUT
            );
            cpex_shutdown(handle);

            // With no handler on identity.resolve the plain input
            // dispatches and allows.
            let bare = build_test_engine();
            assert_eq!(
                invoke_named(bare, "identity.resolve", PAYLOAD_IDENTITY, &input),
                RC_OK
            );
            cpex_shutdown(bare);
        }
    }

    /// An install that panicked stays failed: a retry returns RC_PANIC
    /// rather than RC_OK over a half-installed engine.
    #[test]
    fn cpex_apl_install_after_a_panic_keeps_failing() {
        unsafe {
            let handle = cpex_engine_new_default();
            (*handle)
                .fail_install
                .store(true, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(cpex_apl_install(handle, 0), RC_PANIC);

            // Clearing the injection does not help: the state is final.
            (*handle)
                .fail_install
                .store(false, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(cpex_apl_install(handle, 0), RC_PANIC);
            assert_eq!(
                *(*handle).install_state.lock().unwrap(),
                apl::InstallState::Failed
            );
            cpex_shutdown(handle);
        }
    }

    /// An identity-jwt plugin whose JWKS sits on a loopback port nothing
    /// listens on, plus one APL route. With private destinations blocked
    /// the fetch never leaves the process, so initialize soft-fails
    /// without touching the network.
    const APL_YAML: &str = r#"
plugins:
  - name: jwt
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      header: Authorization
      trusted_issuers:
        - issuer: "https://idp.test.local"
          audiences: ["test-api"]
          algorithms: ["ES256"]
          decoding_key:
            kind: jwks_url
            url: "http://127.0.0.1:9/jwks"
            insecure_http: true
      claim_mapper: standard
global:
  authentication: [jwt]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "require(role.hr)"
"#;

    unsafe fn load(handle: *const CpexEngineInner, yaml: &str) -> c_int {
        // SAFETY: forwarded caller contract; `yaml` is borrowed for the call.
        unsafe { cpex_load_config(handle, yaml.as_ptr() as *const c_char, yaml.len() as c_int) }
    }

    unsafe fn has_hook(handle: *const CpexEngineInner, hook: &str) -> c_int {
        // SAFETY: forwarded caller contract; `hook` is borrowed for the call.
        unsafe { cpex_has_hooks_for(handle, hook.as_ptr() as *const c_char, hook.len() as c_int) }
    }

    /// Full APL flow through the FFI surface: default engine, then
    /// cpex_apl_install (bundled factories and the APL visitor), then
    /// cpex_load_config over an APL-annotated YAML using a bundled plugin
    /// kind (`identity/jwt`), then cpex_initialize. Proves the visitor walk
    /// runs and the bundled factory is reachable.
    #[test]
    fn cpex_apl_install_then_load_apl_config_initializes() {
        unsafe {
            let handle = cpex_engine_new_default();

            assert_eq!(cpex_apl_install(handle, 0), RC_OK);
            assert_eq!(
                load(handle, APL_YAML),
                RC_OK,
                "load of APL config should succeed"
            );
            assert_eq!(cpex_initialize(handle), RC_OK);

            assert_eq!(cpex_plugin_count(handle), 1);
            assert_eq!(has_hook(handle, "identity.resolve"), 1);
            // The route's APL handler sits on the CMF tool hook.
            assert_eq!(has_hook(handle, "cmf.tool_pre_invoke"), 1);

            cpex_shutdown(handle);
        }
    }

    /// The one-shot constructor stays builtin-free: a config naming a
    /// bundled kind fails to load because no factory is registered.
    #[test]
    fn cpex_engine_new_does_not_install_builtins() {
        unsafe {
            let handle =
                cpex_engine_new(APL_YAML.as_ptr() as *const c_char, APL_YAML.len() as c_int);
            assert!(
                handle.is_null(),
                "identity/jwt must not resolve without cpex_apl_install"
            );
        }
    }

    /// A second install is a no-op: it returns RC_OK, ignores its flags,
    /// and a later config load yields the same plugin and hook layout as
    /// a single install.
    #[test]
    fn cpex_apl_install_twice_is_a_no_op() {
        unsafe {
            let once = cpex_engine_new_default();
            assert_eq!(cpex_apl_install(once, 0), RC_OK);

            let twice = cpex_engine_new_default();
            assert_eq!(cpex_apl_install(twice, 0), RC_OK);
            assert_eq!(
                cpex_apl_install(twice, CPEX_APL_ALLOW_PRIVATE_DESTINATIONS),
                RC_OK
            );

            for handle in [once, twice] {
                assert_eq!(load(handle, APL_YAML), RC_OK);
                assert_eq!(cpex_initialize(handle), RC_OK);
            }

            assert_eq!(cpex_plugin_count(once), cpex_plugin_count(twice));
            assert_eq!(
                (*once).engine.plugin_names(),
                (*twice).engine.plugin_names()
            );
            for hook in [
                "identity.resolve",
                "cmf.tool_pre_invoke",
                "cmf.tool_post_invoke",
            ] {
                assert_eq!(has_hook(once, hook), has_hook(twice, hook), "{hook}");
            }

            cpex_shutdown(once);
            cpex_shutdown(twice);
        }
    }
}
