// Location: ./crates/cpex-ffi/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX FFI — C API for embedding the CPEX runtime.
//
// Exports extern "C" functions that Go (via cgo), Python (via ctypes/cffi),
// and other languages can call. Payloads and extensions cross the boundary
// as MessagePack bytes. ContextTable and BackgroundTasks are opaque handles.
//
// Each PluginManager owns its own tokio runtime so async plugin execution
// works from synchronous cgo calls.

use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::OnceLock;
use std::time::Duration;

use cpex_core::context::PluginContextTable;
use cpex_core::executor::BackgroundTasks;
use cpex_core::extensions::Extensions;
use cpex_core::hooks::payload::PluginPayload;
use cpex_core::manager::PluginManager;

// ---------------------------------------------------------------------------
// FFI Result Codes
// ---------------------------------------------------------------------------
//
// FFI functions return c_int. 0 means success; negative codes classify
// failures so the Go (or other-language) caller can produce a typed
// error rather than a single opaque "invoke failed" string. The codes
// are stable wire ABI — additions go at the end with a fresh value;
// don't renumber.
//
// Mapped on the Go side in `go/cpex/manager.go::errorFromRC`.

/// Operation succeeded.
pub const RC_OK: c_int = 0;
/// Manager handle is null or shut down.
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

/// Outer wall-clock timeout for any FFI-driven async call. Per-plugin
/// `tokio::time::timeout` only catches cooperative-async timeouts; this
/// catches CPU-bound or thread-blocking plugins that never yield. Set
/// generously — bigger than any reasonable per-plugin timeout — so the
/// usual case never hits this bound.
const FFI_WALL_CLOCK_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Shared Tokio Runtime
// ---------------------------------------------------------------------------
//
// One process-singleton runtime serves every manager rather than each
// `cpex_manager_new` building its own. With many managers (multi-tenant
// hosts that create one per request, dynamic plugin reload, etc.) the
// per-manager model exploded thread count: 100 managers × num_cpus
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
    let raw = std::env::var(ENV_WORKER_THREADS).ok()?;
    match raw.parse::<usize>() {
        Ok(n) if n > 0 => Some(n),
        Ok(_) => {
            tracing::warn!(
                "cpex-ffi: {}={} is not a positive integer; using num_cpus default",
                ENV_WORKER_THREADS,
                raw,
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                "cpex-ffi: {}={:?} is not parseable as a positive integer; using num_cpus default",
                ENV_WORKER_THREADS,
                raw,
            );
            None
        }
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
/// Must be called *before* any `cpex_manager_new` / `cpex_manager_new_default`
/// call — once a manager has been created the runtime is fixed for
/// the process lifetime. Returns `RC_OK` on success or
/// `RC_INVALID_INPUT` if the runtime has already been initialized
/// (or if `worker_threads` is non-positive).
///
/// Use case: multi-tenant hosts that want to bound total worker
/// threads regardless of how many `PluginManager`s are alive.
///
/// Precedence: this FFI call beats `CPEX_FFI_WORKER_THREADS` (the env
/// var is read only on lazy init via `shared_runtime()`; an explicit
/// `set` here populates the OnceLock first and short-circuits that
/// path). Operators can set the env var as a default; host code can
/// override.
///
/// # Safety
/// Safe to call from a single thread before any manager creation.
/// Calling after a manager exists is well-defined (returns
/// `RC_INVALID_INPUT`) but does not change the active runtime.
#[no_mangle]
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
        }
    };
    match SHARED_RUNTIME.set(rt) {
        Ok(()) => RC_OK,
        Err(_) => {
            // Runtime already initialized — caller should have set
            // this before any manager creation.
            tracing::warn!(
                "cpex_configure_runtime: runtime already initialized; \
                 configuration ignored. Call before any cpex_manager_new.",
            );
            RC_INVALID_INPUT
        }
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
        }
        Err(_panic_payload) => {
            tracing::error!(
                "FFI {}: plugin panicked across FFI boundary — caught to \
                 prevent UB; returning failure to caller",
                op_name,
            );
            SafeRun::Panicked
        }
    }
}

// ---------------------------------------------------------------------------
// Payload Type Registry
// ---------------------------------------------------------------------------

/// Payload type IDs — must match Go constants.
pub const PAYLOAD_GENERIC: u8 = 0;
pub const PAYLOAD_CMF_MESSAGE: u8 = 1;

/// Deserialize a MessagePack payload based on its type ID.
/// Array-indexed — O(1) lookup, zero allocation.
fn deserialize_payload(payload_type: u8, bytes: &[u8]) -> Result<Box<dyn PluginPayload>, String> {
    match payload_type {
        PAYLOAD_GENERIC => {
            let value: serde_json::Value = rmp_serde::from_slice(bytes)
                .map_err(|e| format!("generic payload deserialize failed: {}", e))?;
            Ok(Box::new(GenericPayload { value }))
        }
        PAYLOAD_CMF_MESSAGE => {
            let msg: cpex_core::cmf::MessagePayload = rmp_serde::from_slice(bytes)
                .map_err(|e| format!("CMF payload deserialize failed: {}", e))?;
            Ok(Box::new(msg))
        }
        _ => Err(format!("unknown payload type: {}", payload_type)),
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
        .downcast_ref::<cpex_core::cmf::MessagePayload>()
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
    Err("unknown payload type, cannot serialize across FFI".to_string())
}

// ---------------------------------------------------------------------------
// Opaque Handle Types
// ---------------------------------------------------------------------------

/// Opaque handle to a PluginManager.
///
/// All managers share the process-singleton runtime returned by
/// `shared_runtime()` — see the `SHARED_RUNTIME` doc-comment for why.
pub struct CpexManagerInner {
    pub manager: PluginManager,
}

/// Opaque handle to a ContextTable (Rust-owned, not serialized).
pub struct CpexContextTableInner {
    table: PluginContextTable,
}

/// Opaque handle to BackgroundTasks (Rust-owned, not serialized).
pub struct CpexBackgroundTasksInner {
    tasks: BackgroundTasks,
}

// ---------------------------------------------------------------------------
// Helper: safe string from C
// ---------------------------------------------------------------------------

unsafe fn c_str_to_slice<'a>(ptr: *const c_char, len: c_int) -> Option<&'a str> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len as usize);
    std::str::from_utf8(bytes).ok()
}

unsafe fn c_bytes_to_slice<'a>(ptr: *const u8, len: c_int) -> Option<&'a [u8]> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len as usize))
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
    let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
    unsafe {
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            return (ptr::null_mut(), 0);
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);
        (ptr, len as c_int)
    }
}

// ---------------------------------------------------------------------------
// Manager Lifecycle
// ---------------------------------------------------------------------------

/// Create a new PluginManager from a YAML config string.
///
/// Returns an opaque handle. The manager owns a tokio runtime for
/// async plugin execution. Returns NULL on failure.
///
/// # Safety
/// `config_yaml` must be a valid pointer to `config_len` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn cpex_manager_new(
    config_yaml: *const c_char,
    config_len: c_int,
) -> *mut CpexManagerInner {
    let yaml = match c_str_to_slice(config_yaml, config_len) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    let cpex_config = match cpex_core::config::parse_config(yaml) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("cpex_manager_new: config parse failed: {}", e);
            return ptr::null_mut();
        }
    };

    // Touch the shared runtime so any later cpex_configure_runtime
    // call returns RC_INVALID_INPUT — communicates "you missed the
    // window" to the operator, instead of letting the configure call
    // silently no-op.
    let _ = shared_runtime();

    let manager = PluginManager::default();

    // Load config — factories must be registered separately via cpex_register_factory
    if let Err(e) = manager.load_config(cpex_config) {
        tracing::error!("cpex_manager_new: load_config failed: {}", e);
        return ptr::null_mut();
    }

    Box::into_raw(Box::new(CpexManagerInner { manager }))
}

/// Create a new PluginManager with default config (no YAML).
///
/// Useful when registering plugins programmatically.
#[no_mangle]
pub extern "C" fn cpex_manager_new_default() -> *mut CpexManagerInner {
    let _ = shared_runtime();
    let manager = PluginManager::default();
    Box::into_raw(Box::new(CpexManagerInner { manager }))
}

/// Load a YAML config into an existing manager.
///
/// Factories must be registered before calling this function.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `mgr` must be a valid handle. `config_yaml` must be valid UTF-8.
/// `mgr` is `*const` — `PluginManager::load_config` takes `&self` after
/// the ArcSwap snapshot refactor (no exclusive access needed). Two
/// callers loading config concurrently is safe; the snapshot swap is
/// atomic copy-on-write, so they see consistent state per call.
#[no_mangle]
pub unsafe extern "C" fn cpex_load_config(
    mgr: *const CpexManagerInner,
    config_yaml: *const c_char,
    config_len: c_int,
) -> c_int {
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    let yaml = match c_str_to_slice(config_yaml, config_len) {
        Some(s) => s,
        None => return RC_INVALID_INPUT,
    };

    let cpex_config = match cpex_core::config::parse_config(yaml) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("cpex_load_config: config parse failed: {}", e);
            return RC_PARSE_ERROR;
        }
    };

    // load_config is sync (no .await), but we still wrap in catch_unwind
    // so a panic in serde / config validation doesn't unwind across FFI.
    let load_result = catch_unwind(AssertUnwindSafe(|| inner.manager.load_config(cpex_config)));
    match load_result {
        Ok(Ok(())) => RC_OK,
        Ok(Err(e)) => {
            tracing::error!("cpex_load_config: load_config failed: {}", e);
            RC_PIPELINE_ERROR
        }
        Err(_panic) => {
            tracing::error!("cpex_load_config: panic caught at FFI boundary");
            RC_PANIC
        }
    }
}

/// Initialize all registered plugins.
///
/// Returns 0 on success, -1 on failure (including timeout / panic).
///
/// # Safety
/// `mgr` must be a valid handle from `cpex_manager_new`.
/// `mgr` is `*const` — `PluginManager::initialize` takes `&self`.
#[no_mangle]
pub unsafe extern "C" fn cpex_initialize(mgr: *const CpexManagerInner) -> c_int {
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    match run_safely(inner.manager.initialize(), "cpex_initialize") {
        SafeRun::Ok(Ok(())) => RC_OK,
        SafeRun::Ok(Err(e)) => {
            tracing::error!("cpex_initialize: {}", e);
            RC_PIPELINE_ERROR
        }
        other => other.rc(), // RC_TIMEOUT or RC_PANIC; already logged
    }
}

/// Shutdown all plugins and free the manager.
///
/// `mgr` stays `*mut` here because we consume the Box (this is the one
/// place we genuinely take exclusive ownership — destroying the
/// allocation). All other entry points use `*const`.
///
/// # Safety
/// `mgr` must be a valid handle from `cpex_manager_new`. After this
/// call, the handle is invalid and must not be used.
#[no_mangle]
pub unsafe extern "C" fn cpex_shutdown(mgr: *mut CpexManagerInner) {
    if mgr.is_null() {
        return;
    }
    let inner = Box::from_raw(mgr);
    // Wrap shutdown in catch_unwind + timeout so a misbehaving plugin
    // can't hang teardown forever or unwind across the FFI boundary.
    // We don't have a return value here — `inner` is dropped at function
    // end either way, freeing the manager and runtime.
    let _ = run_safely(inner.manager.shutdown(), "cpex_shutdown");
}

/// Check if any plugins are registered for a hook name.
///
/// Returns 1 (true) or 0 (false). No serialization — just a hash lookup.
///
/// # Safety
/// `mgr` must be valid. `hook_name` must point to `hook_len` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn cpex_has_hooks_for(
    mgr: *const CpexManagerInner,
    hook_name: *const c_char,
    hook_len: c_int,
) -> c_int {
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => return 0,
    };
    let name = match c_str_to_slice(hook_name, hook_len) {
        Some(s) => s,
        None => return 0,
    };
    if inner.manager.has_hooks_for(name) {
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
/// `mgr` must be valid.
#[no_mangle]
pub unsafe extern "C" fn cpex_plugin_count(mgr: *const CpexManagerInner) -> c_int {
    match mgr.as_ref() {
        Some(m) => m.manager.plugin_count() as c_int,
        None => 0,
    }
}

/// Whether the manager has been initialized (i.e., `cpex_initialize`
/// returned successfully and `cpex_shutdown` has not been called).
///
/// Returns 1 if initialized, 0 otherwise (including null mgr).
///
/// # Safety
/// `mgr` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn cpex_is_initialized(mgr: *const CpexManagerInner) -> c_int {
    match mgr.as_ref() {
        Some(m) if m.manager.is_initialized() => 1,
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
/// `mgr` must be valid. Output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn cpex_plugin_names(
    mgr: *const CpexManagerInner,
    names_msgpack_out: *mut *mut u8,
    names_len_out: *mut c_int,
) -> c_int {
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    let names = inner.manager.plugin_names();
    let bytes = match rmp_serde::to_vec_named(&names) {
        Ok(b) => b,
        Err(_) => return RC_SERIALIZE_ERROR,
    };
    let (ptr, len) = alloc_bytes(&bytes);
    *names_msgpack_out = ptr;
    *names_len_out = len;
    RC_OK
}

// ---------------------------------------------------------------------------
// Hook Invocation
// ---------------------------------------------------------------------------

/// Invoke a hook by name.
///
/// Payload and extensions are passed as MessagePack bytes.
/// ContextTable is an opaque handle (NULL for first invocation).
/// Returns MessagePack-encoded PipelineResult + opaque handles for
/// context table and background tasks.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// All pointer parameters must be valid or NULL where documented.
/// `mgr` is `*const` — `PluginManager::invoke_by_name` takes `&self`
/// after the ArcSwap snapshot refactor. The previous `*mut` + `as_mut()`
/// shape produced aliased `&mut` references when two goroutines called
/// this concurrently — UB regardless of what the called code did. The
/// `&self` API plus `*const` here is sound for parallel dispatch.
#[no_mangle]
pub unsafe extern "C" fn cpex_invoke(
    mgr: *const CpexManagerInner,
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
    // Validate manager handle
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => return RC_INVALID_HANDLE,
    };

    // Parse hook name
    let name = match c_str_to_slice(hook_name, hook_len) {
        Some(s) => s,
        None => return RC_INVALID_INPUT,
    };

    // Deserialize payload using the type registry
    let payload_bytes = match c_bytes_to_slice(payload_msgpack, payload_len) {
        Some(b) => b,
        None => return RC_INVALID_INPUT,
    };

    let payload: Box<dyn PluginPayload> = match deserialize_payload(payload_type, payload_bytes) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("cpex_invoke: {}", e);
            return RC_PARSE_ERROR;
        }
    };

    // Deserialize extensions from MessagePack
    let extensions: Extensions = if extensions_len > 0 {
        let ext_bytes = match c_bytes_to_slice(extensions_msgpack, extensions_len) {
            Some(b) => b,
            None => return RC_INVALID_INPUT,
        };
        match rmp_serde::from_slice(ext_bytes) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("cpex_invoke: extensions deserialize failed: {}", e);
                return RC_PARSE_ERROR;
            }
        }
    } else {
        Extensions::default()
    };

    // Get or create context table
    let ctx_table: Option<PluginContextTable> = if context_table.is_null() {
        None
    } else {
        let ct = Box::from_raw(context_table);
        Some(ct.table)
    };

    // Invoke the hook with wall-clock timeout + panic catch.
    let (mut result, bg) = match run_safely(
        inner
            .manager
            .invoke_by_name(name, payload, extensions, ctx_table),
        "cpex_invoke",
    ) {
        SafeRun::Ok(r) => r,
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
                result.errors.push(cpex_core::error::PluginErrorRecord {
                    plugin_name: "<ffi>".to_string(),
                    message: format!("modified payload could not be serialized across FFI: {e}"),
                    code: Some("ffi_serialize_error".to_string()),
                    details: std::collections::HashMap::new(),
                    proto_error_code: None,
                });
                (payload_type, None)
            }
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
        modified_extensions: modified_extensions_bytes,
    };

    let result_bytes = match rmp_serde::to_vec_named(&ffi_result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("cpex_invoke: result serialize failed: {}", e);
            return RC_SERIALIZE_ERROR;
        }
    };

    // Return result bytes
    let (ptr, len) = alloc_bytes(&result_bytes);
    *result_msgpack_out = ptr;
    *result_len_out = len;

    // Return context table as opaque handle
    *context_table_out = Box::into_raw(Box::new(CpexContextTableInner {
        table: result.context_table,
    }));

    // Return background tasks as opaque handle
    *bg_handle_out = Box::into_raw(Box::new(CpexBackgroundTasksInner { tasks: bg }));

    RC_OK
}

// ---------------------------------------------------------------------------
// Background Tasks
// ---------------------------------------------------------------------------

/// Wait for all background tasks to complete.
///
/// Returns MessagePack-encoded errors (empty array if none).
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `bg_handle` must be a valid handle from `cpex_invoke`.
/// After this call, the handle is consumed and invalid.
/// `mgr` is `*const` — only the runtime is borrowed (`&self`).
#[no_mangle]
pub unsafe extern "C" fn cpex_wait_background(
    mgr: *const CpexManagerInner,
    bg_handle: *mut CpexBackgroundTasksInner,
    errors_msgpack_out: *mut *mut u8,
    errors_len_out: *mut c_int,
) -> c_int {
    let inner = match mgr.as_ref() {
        Some(m) => m,
        None => {
            // Consume `bg_handle` even on the failure path — the Go
            // caller has already nil'd its reference, so without
            // dropping the Box here we'd leak the BackgroundTasks
            // allocation (and its still-running task handles).
            if !bg_handle.is_null() {
                drop(Box::from_raw(bg_handle));
            }
            return RC_INVALID_HANDLE;
        }
    };

    if bg_handle.is_null() {
        let empty: Vec<cpex_core::error::PluginErrorRecord> = Vec::new();
        let (ptr, len) = alloc_bytes(&rmp_serde::to_vec_named(&empty).unwrap());
        *errors_msgpack_out = ptr;
        *errors_len_out = len;
        return RC_OK;
    }

    let bg = Box::from_raw(bg_handle);
    // `inner` is now unused but the borrow proved the manager is alive
    // for the duration of this call (the read lock on the Go side).
    let _ = inner;
    let errors = match run_safely(bg.tasks.wait_for_background_tasks(), "cpex_wait_background") {
        SafeRun::Ok(errs) => errs,
        other => return other.rc(), // RC_TIMEOUT or RC_PANIC; already logged
    };

    // Flatten each Rust PluginError variant into the canonical wire
    // shape so Go callers get structured fields (plugin_name, code,
    // details) instead of a stringified Display impl.
    let ffi_errors: Vec<cpex_core::error::PluginErrorRecord> = errors
        .iter()
        .map(cpex_core::error::PluginErrorRecord::from)
        .collect();
    let error_bytes = match rmp_serde::to_vec_named(&ffi_errors) {
        Ok(b) => b,
        Err(_) => return RC_SERIALIZE_ERROR,
    };

    let (ptr, len) = alloc_bytes(&error_bytes);
    *errors_msgpack_out = ptr;
    *errors_len_out = len;

    RC_OK
}

/// Free a background tasks handle without waiting.
///
/// Tasks continue running in the tokio runtime.
///
/// # Safety
/// `bg_handle` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn cpex_free_background(bg_handle: *mut CpexBackgroundTasksInner) {
    if !bg_handle.is_null() {
        drop(Box::from_raw(bg_handle));
    }
}

// ---------------------------------------------------------------------------
// Context Table
// ---------------------------------------------------------------------------

/// Free a context table handle.
///
/// # Safety
/// `ct` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn cpex_free_context_table(ct: *mut CpexContextTableInner) {
    if !ct.is_null() {
        drop(Box::from_raw(ct));
    }
}

// ---------------------------------------------------------------------------
// Memory Management
// ---------------------------------------------------------------------------

/// Free a byte buffer allocated by the FFI layer.
///
/// # Safety
/// `ptr` must have been allocated by this library (from `cpex_invoke`
/// or `cpex_wait_background`). `len` must match the original allocation.
#[no_mangle]
pub unsafe extern "C" fn cpex_free_bytes(ptr: *mut u8, len: c_int) {
    if ptr.is_null() || len <= 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(len as usize, 1).unwrap();
    std::alloc::dealloc(ptr, layout);
}

// ---------------------------------------------------------------------------
// FFI Result Types — serialized to MessagePack for the caller
// ---------------------------------------------------------------------------

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
    violation: Option<cpex_core::error::PluginViolation>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    errors: Vec<cpex_core::error::PluginErrorRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    /// Payload type ID — tells the Go caller how to deserialize.
    payload_type: u8,
    /// Modified payload as raw MessagePack bytes (if a plugin modified it).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes_opt")]
    modified_payload: Option<Vec<u8>>,
    /// Modified extensions as raw MessagePack bytes (if a plugin modified them).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes_opt")]
    modified_extensions: Option<Vec<u8>>,
}

/// Helper for serializing Option<Vec<u8>> as binary in MessagePack.
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

// ---------------------------------------------------------------------------
// Generic Payload — wraps a deserialized MessagePack value
// ---------------------------------------------------------------------------

/// A generic payload that wraps a deserialized serde_json::Value.
///
/// Used for FFI dispatch when the concrete payload type isn't known
/// at compile time. The value was deserialized from MessagePack on
/// the Go side and will be passed to Rust plugins as-is.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericPayload {
    pub value: serde_json::Value,
}

cpex_core::impl_plugin_payload!(GenericPayload);

// ---------------------------------------------------------------------------
// FFI unit tests
// ---------------------------------------------------------------------------
//
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
    use cpex_core::hooks::payload::Extensions;
    use cpex_core::hooks::trait_def::HookTypeDef;
    use cpex_core::hooks::PluginResult;
    use cpex_core::plugin::{Plugin, PluginConfig, PluginMode};

    // --- Test scaffolding -----------------------------------------------------

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

    impl cpex_core::hooks::HookHandler<TestHook> for PanickingPlugin {
        async fn handle(
            &self,
            _payload: &GenericPayload,
            _extensions: &Extensions,
            _ctx: &mut cpex_core::context::PluginContext,
        ) -> PluginResult<GenericPayload> {
            panic!("simulated panic from PanickingPlugin");
        }
    }

    /// Build an FFI-shaped manager for testing. Bypasses
    /// `cpex_manager_new` so we can register Rust plugins directly via
    /// the manager's typed API.
    fn build_test_manager() -> *mut CpexManagerInner {
        // Touch the shared runtime so it's initialized; tests use it
        // rather than a per-manager runtime.
        let _ = shared_runtime();
        let manager = cpex_core::manager::PluginManager::default();
        Box::into_raw(Box::new(CpexManagerInner { manager }))
    }

    fn register_panicking_plugin(mgr: &CpexManagerInner) {
        let cfg = PluginConfig {
            name: "panicker".into(),
            kind: "test".into(),
            hooks: vec!["test_hook".into()],
            mode: PluginMode::Sequential,
            ..Default::default()
        };
        let plugin = Arc::new(PanickingPlugin { cfg: cfg.clone() });
        mgr.manager
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
        mgr: *const CpexManagerInner,
        payload_type: u8,
        payload: &[u8],
    ) -> c_int {
        let hook_name = b"test_hook";
        let mut result_ptr: *mut u8 = ptr::null_mut();
        let mut result_len: c_int = 0;
        let mut ct_out: *mut CpexContextTableInner = ptr::null_mut();
        let mut bg_out: *mut CpexBackgroundTasksInner = ptr::null_mut();

        let rc = cpex_invoke(
            mgr,
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
        );

        // Drain any output buffers / handles to avoid leaks across tests.
        if !result_ptr.is_null() {
            cpex_free_bytes(result_ptr, result_len);
        }
        if !ct_out.is_null() {
            cpex_free_context_table(ct_out);
        }
        if !bg_out.is_null() {
            cpex_free_background(bg_out);
        }
        rc
    }

    // --- Tests ----------------------------------------------------------------

    /// Panic in a plugin must be caught at the FFI boundary and mapped
    /// to `RC_PANIC` rather than unwinding across `extern "C"` (UB on
    /// Rust < 1.81; abort on >= 1.81). Direct regression for P0 #2.
    #[test]
    fn cpex_invoke_returns_rc_panic_when_plugin_panics() {
        let mgr = build_test_manager();
        // Defer cleanup so a test failure doesn't leak the manager.
        struct ManagerGuard(*mut CpexManagerInner);
        impl Drop for ManagerGuard {
            fn drop(&mut self) {
                unsafe {
                    cpex_shutdown(self.0);
                }
            }
        }
        let _guard = ManagerGuard(mgr);

        unsafe {
            let inner = &*mgr;
            register_panicking_plugin(inner);
            // Manager must be initialized for the pipeline to dispatch.
            let init_rc = cpex_initialize(mgr);
            assert_eq!(init_rc, RC_OK, "init should succeed");

            // Invoke with the registered hook — plugin panics, caught
            // by run_safely's catch_unwind, mapped to RC_PANIC.
            let bytes = payload_bytes("trigger");
            let rc = invoke_for_test(mgr, PAYLOAD_GENERIC, &bytes);
            assert_eq!(
                rc, RC_PANIC,
                "panic should be caught and surfaced as RC_PANIC, got {}",
                rc,
            );
        }
    }

    /// Invoking with an unknown `payload_type` must return
    /// `RC_PARSE_ERROR` — the deserialize_payload registry rejects
    /// unknown discriminators with a typed error code rather than a
    /// generic failure.
    #[test]
    fn cpex_invoke_returns_rc_parse_error_on_unknown_payload_type() {
        let mgr = build_test_manager();
        struct ManagerGuard(*mut CpexManagerInner);
        impl Drop for ManagerGuard {
            fn drop(&mut self) {
                unsafe {
                    cpex_shutdown(self.0);
                }
            }
        }
        let _guard = ManagerGuard(mgr);

        unsafe {
            let inner = &*mgr;
            register_panicking_plugin(inner); // need *some* plugin so dispatch runs
            assert_eq!(cpex_initialize(mgr), RC_OK);

            // Unknown payload type — dispatch never reaches the plugin.
            let bytes = payload_bytes("trigger");
            let rc = invoke_for_test(mgr, 99 /* not in registry */, &bytes);
            assert_eq!(
                rc, RC_PARSE_ERROR,
                "unknown payload_type should map to RC_PARSE_ERROR, got {}",
                rc,
            );
        }
    }

    /// `worker_threads_from_env` parses CPEX_FFI_WORKER_THREADS into
    /// a positive count, returning None for unset / zero / negative /
    /// unparseable. This isolates the env-parsing logic from the
    /// OnceLock-init path so we can test it deterministically.
    #[test]
    fn worker_threads_from_env_parses_correctly() {
        // Use a unique env var name per test invocation isn't possible
        // (the function reads ENV_WORKER_THREADS specifically), so we
        // serialize manipulation: set, read, restore. Run-time tests
        // don't currently parallelize this var across threads.
        let prev = std::env::var(ENV_WORKER_THREADS).ok();

        // SAFETY: tests are single-threaded with respect to this env
        // var (no other test reads/writes it). std::env::set_var is
        // unsafe in multi-threaded programs reading other env vars
        // concurrently; we accept that risk in the test harness.
        let restore = |v: Option<String>| unsafe {
            match v {
                Some(s) => std::env::set_var(ENV_WORKER_THREADS, s),
                None => std::env::remove_var(ENV_WORKER_THREADS),
            }
        };

        unsafe {
            std::env::set_var(ENV_WORKER_THREADS, "8");
            assert_eq!(worker_threads_from_env(), Some(8));

            std::env::set_var(ENV_WORKER_THREADS, "0");
            assert_eq!(worker_threads_from_env(), None, "zero should fall back");

            std::env::set_var(ENV_WORKER_THREADS, "garbage");
            assert_eq!(
                worker_threads_from_env(),
                None,
                "unparseable should fall back"
            );

            std::env::remove_var(ENV_WORKER_THREADS);
            assert_eq!(worker_threads_from_env(), None, "unset should be None");
        }

        restore(prev);
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
    /// or `cpex_manager_new` call), subsequent configure attempts must
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

    /// A null manager handle must return `RC_INVALID_HANDLE` from
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
}
