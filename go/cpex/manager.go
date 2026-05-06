// Location: ./go/cpex/manager.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// PluginManager — Go wrapper for the CPEX plugin runtime.
//
// Owns the lifecycle of the Rust PluginManager via cgo. Provides
// the public API that Go host systems call to register factories,
// load config, initialize plugins, and invoke hooks.
//
// Lifecycle:
//
//	NewPluginManagerDefault() → RegisterFactories() → LoadConfig() → Initialize() → InvokeByName() → Shutdown()
//
// Payloads and extensions are serialized to MessagePack when
// crossing the FFI boundary. ContextTable and BackgroundTasks
// are opaque handles to Rust-owned data.

package cpex

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/vmihailenco/msgpack/v5"
)

/*
#include <stdint.h>
#include <stdlib.h>

// Opaque handles
typedef void* CpexManager;
typedef void* CpexContextTable;
typedef void* CpexBackgroundTasks;

// Extern declarations - implemented in libcpex_ffi.
//
// These are duplicated with ffi.go's preamble. CGO does NOT merge
// declarations across multiple files' preambles in a single package -
// each file's `import "C"` resolves only against its own preceding
// comment block. The reviewer's "remove these, CGO resolves
// package-wide" suggestion was tested and didn't work; CGO reports
// "could not determine what C.cpex_X refers to" for any function
// declared only in a sibling file's preamble.
//
// If you change a signature, edit BOTH this block and ffi.go's. The
// build will fail loudly on a mismatch (Go's C type system catches
// it), but the duplication is unavoidable until either:
//   - all cgo entry points move to ffi.go (refactor), or
//   - we generate the C header via cbindgen and #include it from
//     both files.
extern int cpex_configure_runtime(int worker_threads);
extern CpexManager cpex_manager_new(const char* config_yaml, int config_len);
extern CpexManager cpex_manager_new_default();
extern int cpex_load_config(CpexManager mgr, const char* config_yaml, int config_len);
extern int cpex_initialize(CpexManager mgr);
extern void cpex_shutdown(CpexManager mgr);
extern int cpex_has_hooks_for(CpexManager mgr, const char* hook_name, int hook_len);
extern int cpex_plugin_count(CpexManager mgr);
extern int cpex_is_initialized(CpexManager mgr);
extern int cpex_plugin_names(CpexManager mgr, uint8_t** names_msgpack_out, int* names_len_out);
extern int cpex_invoke(
    CpexManager mgr,
    const char* hook_name, int hook_len,
    uint8_t payload_type,
    const uint8_t* payload_msgpack, int payload_len,
    const uint8_t* extensions_msgpack, int extensions_len,
    CpexContextTable context_table,
    uint8_t** result_msgpack_out, int* result_len_out,
    CpexContextTable* context_table_out,
    CpexBackgroundTasks* bg_handle_out
);
extern int cpex_wait_background(
    CpexManager mgr,
    CpexBackgroundTasks bg_handle,
    uint8_t** errors_msgpack_out, int* errors_len_out
);
extern void cpex_free_background(CpexBackgroundTasks bg_handle);
extern void cpex_free_context_table(CpexContextTable ct);
extern void cpex_free_bytes(uint8_t* ptr, int len);
*/
import "C"

// PluginManager manages the lifecycle of CPEX plugins and hook dispatch.
// Wraps the Rust PluginManager — all plugin execution happens in Rust.
//
// Concurrency: `mu` serializes lifecycle (Shutdown, finalizer) against
// in-flight cgo calls. Operations (Invoke, Initialize, queries) take
// the *read* lock and may run in parallel with each other — the
// underlying Rust API is `&self` and ArcSwap-backed, so concurrent
// dispatch is safe. `Shutdown` and the GC finalizer take the *write*
// lock so the C handle can't be freed while a cgo call is mid-flight.
type PluginManager struct {
	mu     sync.RWMutex
	handle C.CpexManager // protected by mu; nil after Shutdown
}

// ContextTable holds per-plugin context state across hook invocations.
// Opaque handle to Rust-owned data — not serialized.
type ContextTable struct {
	handle C.CpexContextTable
}

// BackgroundTasks holds fire-and-forget task handles.
// Opaque handle to Rust-owned data — not serialized.
//
// Holds *PluginManager (not the raw C handle) so `Wait()` can check
// `mgr.handle != nil` under the manager's RWMutex — preventing a
// use-after-free if the manager was Shutdown after the invoke that
// produced this `BackgroundTasks`.
type BackgroundTasks struct {
	handle C.CpexBackgroundTasks
	mgr    *PluginManager
}

// ConfigureRuntime sets the worker thread count for the shared tokio
// runtime that backs every PluginManager in the process. Must be
// called before the first NewPluginManager — once a manager has
// been created the runtime is fixed for the process lifetime.
//
// Precedence: ConfigureRuntime > CPEX_FFI_WORKER_THREADS env var >
// num_cpus default. Returns ErrCpexInvalidInput if workerThreads <= 0
// or the runtime has already been initialized.
func ConfigureRuntime(workerThreads int) error {
	rc := C.cpex_configure_runtime(C.int(workerThreads))
	return errorFromRC(int(rc), "ConfigureRuntime")
}

// finalizeManager is the GC fallback path when the caller forgot to
// call Shutdown. Takes the write lock so it can't race with an
// explicit Shutdown that's already running.
func finalizeManager(m *PluginManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handle != nil {
		C.cpex_shutdown(m.handle)
		m.handle = nil
	}
}

// NewPluginManager creates a manager from a YAML config string.
// Built-in Rust plugin factories are registered automatically.
func NewPluginManager(yaml string) (*PluginManager, error) {
	cYaml := C.CString(yaml)
	defer C.free(unsafe.Pointer(cYaml))

	handle := C.cpex_manager_new(cYaml, C.int(len(yaml)))
	if handle == nil {
		return nil, errors.New("cpex: failed to create plugin manager from config")
	}

	mgr := &PluginManager{handle: handle}
	runtime.SetFinalizer(mgr, finalizeManager)
	return mgr, nil
}

// NewPluginManagerDefault creates a manager with default config.
// Useful when registering plugins programmatically.
func NewPluginManagerDefault() (*PluginManager, error) {
	handle := C.cpex_manager_new_default()
	if handle == nil {
		return nil, errors.New("cpex: failed to create default plugin manager")
	}

	mgr := &PluginManager{handle: handle}
	runtime.SetFinalizer(mgr, finalizeManager)
	return mgr, nil
}

// FactoryRegistrar is a function that registers plugin factories on the
// manager's internal handle. The handle is an opaque C pointer — callers
// pass it to their own extern C registration function.
type FactoryRegistrar func(handle unsafe.Pointer) error

// RegisterFactories calls fn with the manager's internal C handle,
// allowing callers to register plugin factories via their own FFI.
// Must be called before LoadConfig.
func (m *PluginManager) RegisterFactories(fn FactoryRegistrar) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return fmt.Errorf("RegisterFactories: %w", ErrCpexInvalidHandle)
	}
	return fn(unsafe.Pointer(m.handle))
}

// LoadConfig loads a YAML config string into the manager.
// Factories must be registered before calling this method.
//
// On failure, the returned error wraps one of the typed sentinels
// (ErrCpexInvalidHandle, ErrCpexInvalidInput, ErrCpexParse,
// ErrCpexPipeline, ErrCpexPanic). Use `errors.Is` to classify.
func (m *PluginManager) LoadConfig(yaml string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return fmt.Errorf("LoadConfig: %w", ErrCpexInvalidHandle)
	}

	cYaml := C.CString(yaml)
	defer C.free(unsafe.Pointer(cYaml))

	rc := C.cpex_load_config(m.handle, cYaml, C.int(len(yaml)))
	return errorFromRC(int(rc), "LoadConfig")
}

// Initialize calls Initialize on all registered plugins.
// Must be called before invoking any hooks.
//
// On failure, the returned error wraps one of the typed sentinels
// (ErrCpexInvalidHandle, ErrCpexPipeline, ErrCpexTimeout, ErrCpexPanic).
func (m *PluginManager) Initialize() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return fmt.Errorf("Initialize: %w", ErrCpexInvalidHandle)
	}

	rc := C.cpex_initialize(m.handle)
	return errorFromRC(int(rc), "Initialize")
}

// Shutdown gracefully shuts down all plugins and releases resources.
// After this call, the manager is invalid and must not be used.
//
// Takes the write lock to ensure no in-flight cgo call is racing with
// the destruction of the C handle. Also clears the GC finalizer so
// the finalizer can't fire later and double-free.
func (m *PluginManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handle == nil {
		return
	}
	// Clear the finalizer first — if cpex_shutdown panics or aborts,
	// we still don't want the finalizer to run later and try again.
	runtime.SetFinalizer(m, nil)
	C.cpex_shutdown(m.handle)
	m.handle = nil
}

// HasHooksFor returns true if any plugins are registered for the hook.
// No serialization — just a hash lookup across the FFI boundary.
func (m *PluginManager) HasHooksFor(hookName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return false
	}
	cName := C.CString(hookName)
	defer C.free(unsafe.Pointer(cName))
	return C.cpex_has_hooks_for(m.handle, cName, C.int(len(hookName))) == 1
}

// PluginCount returns the number of registered plugins.
func (m *PluginManager) PluginCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return 0
	}
	return int(C.cpex_plugin_count(m.handle))
}

// IsInitialized reports whether Initialize has been called and Shutdown
// has not. Useful for agent control loops that may inspect manager
// state before deciding whether to dispatch.
func (m *PluginManager) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return false
	}
	return C.cpex_is_initialized(m.handle) == 1
}

// PluginNames returns the names of all registered plugins. Order is
// not stable across calls — the underlying registry uses a HashMap.
func (m *PluginManager) PluginNames() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return nil, fmt.Errorf("PluginNames: %w", ErrCpexInvalidHandle)
	}

	var namesPtr *C.uint8_t
	var namesLen C.int
	rc := C.cpex_plugin_names(m.handle, &namesPtr, &namesLen)
	if rc != 0 {
		return nil, errorFromRC(int(rc), "PluginNames")
	}

	bytes := C.GoBytes(unsafe.Pointer(namesPtr), namesLen)
	C.cpex_free_bytes((*C.uint8_t)(unsafe.Pointer(namesPtr)), namesLen)

	var names []string
	if err := msgpack.Unmarshal(bytes, &names); err != nil {
		return nil, fmt.Errorf("PluginNames: decode failed: %w", err)
	}
	return names, nil
}

// InvokeByName invokes a hook by name with a payload and extensions.
// Payload and extensions are serialized to MessagePack internally.
// The ContextTable is an opaque handle — pass nil on the first call,
// then thread result's ContextTable into subsequent calls.
func (m *PluginManager) InvokeByName(
	hookName string,
	payloadType uint8,
	payload any,
	extensions *Extensions,
	contextTable *ContextTable,
) (*PipelineResult, *ContextTable, *BackgroundTasks, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return nil, nil, nil, fmt.Errorf("InvokeByName: %w", ErrCpexInvalidHandle)
	}

	// Serialize payload to MessagePack
	payloadBytes, err := msgpack.Marshal(payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cpex: payload marshal failed: %w", err)
	}

	// Serialize extensions to MessagePack
	var extBytes []byte
	if extensions != nil {
		extBytes, err = msgpack.Marshal(extensions)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cpex: extensions marshal failed: %w", err)
		}
	}

	// Prepare C args
	cHookName := C.CString(hookName)
	defer C.free(unsafe.Pointer(cHookName))

	// Pass the context-table handle to Rust but DO NOT nil our local
	// reference until we know Rust succeeded. Rust consumes the handle
	// only at the moment of invoke (after all input validation), so
	// pre-invoke failures (bad payload, bad extensions, etc.) leave
	// the handle untouched and the caller's ContextTable remains valid.
	//
	// Caveat: on a post-invoke failure (rare — only result-serialization
	// OOM), Rust has consumed the box but doesn't write ctOut, so the
	// caller's ContextTable handle becomes dangling. The caller should
	// not reuse a ContextTable after an InvokeByName error.
	var ctHandle C.CpexContextTable
	if contextTable != nil {
		ctHandle = contextTable.handle
	}

	var resultPtr *C.uint8_t
	var resultLen C.int
	var ctOut C.CpexContextTable
	var bgOut C.CpexBackgroundTasks

	var payloadPtr *C.uint8_t
	if len(payloadBytes) > 0 {
		payloadPtr = (*C.uint8_t)(unsafe.Pointer(&payloadBytes[0]))
	}

	var extPtr *C.uint8_t
	var extLen C.int
	if len(extBytes) > 0 {
		extPtr = (*C.uint8_t)(unsafe.Pointer(&extBytes[0]))
		extLen = C.int(len(extBytes))
	}

	rc := C.cpex_invoke(
		m.handle,
		cHookName, C.int(len(hookName)),
		C.uint8_t(payloadType),
		payloadPtr, C.int(len(payloadBytes)),
		extPtr, extLen,
		ctHandle,
		&resultPtr, &resultLen,
		&ctOut,
		&bgOut,
	)

	if rc != 0 {
		return nil, nil, nil, errorFromRC(int(rc), "InvokeByName")
	}

	// Rust succeeded — it consumed ctHandle and produced ctOut.
	// NOW it's safe to nil the caller's reference (the original Box
	// was consumed by Rust; its successor is in ctOut).
	if contextTable != nil {
		contextTable.handle = nil
	}

	// Deserialize result from MessagePack
	resultBytes := C.GoBytes(unsafe.Pointer(resultPtr), resultLen)
	C.cpex_free_bytes((*C.uint8_t)(unsafe.Pointer(resultPtr)), resultLen)

	var result PipelineResult
	if err := msgpack.Unmarshal(resultBytes, &result); err != nil {
		return nil, nil, nil, fmt.Errorf("cpex: result unmarshal failed: %w", err)
	}

	// Wrap opaque handles
	resultCT := &ContextTable{handle: ctOut}
	runtime.SetFinalizer(resultCT, func(ct *ContextTable) {
		ct.Close()
	})

	// Hold *PluginManager (not the raw C handle) so Wait() can check
	// mgr.handle != nil under the manager's mutex — preventing UAF
	// if Shutdown is called between this invoke and Wait().
	bg := &BackgroundTasks{handle: bgOut, mgr: m}

	return &result, resultCT, bg, nil
}

// Invoke is the typed invoke path. Calls InvokeByName and deserializes
// the modified payload and extensions into concrete Go types.
//
// Example:
//
//	result, ct, bg, err := cpex.Invoke[cpex.MessagePayload](
//	    mgr, "cmf.tool_pre_invoke", cpex.PayloadCMFMessage,
//	    payload, ext, nil,
//	)
//	if !result.IsDenied() && result.ModifiedPayload != nil {
//	    fmt.Println(result.ModifiedPayload.Message.Role)
//	}
func Invoke[P any](
	m *PluginManager,
	hookName string,
	payloadType uint8,
	payload P,
	extensions *Extensions,
	contextTable *ContextTable,
) (*TypedPipelineResult[P], *ContextTable, *BackgroundTasks, error) {
	raw, ct, bg, err := m.InvokeByName(hookName, payloadType, payload, extensions, contextTable)
	if err != nil {
		return nil, nil, nil, err
	}

	typed := &TypedPipelineResult[P]{
		ContinueProcessing: raw.ContinueProcessing,
		Violation:          raw.Violation,
		Errors:             raw.Errors,
		Metadata:           raw.Metadata,
		PayloadType:        raw.PayloadType,
	}

	// Deserialize modified payload if present
	if len(raw.ModifiedPayload) > 0 {
		var v P
		if err := msgpack.Unmarshal(raw.ModifiedPayload, &v); err != nil {
			return nil, ct, bg, fmt.Errorf("cpex: modified payload unmarshal failed: %w", err)
		}
		typed.ModifiedPayload = &v
	}

	// Deserialize modified extensions if present
	if len(raw.ModifiedExtensions) > 0 {
		var ext Extensions
		if err := msgpack.Unmarshal(raw.ModifiedExtensions, &ext); err != nil {
			return nil, ct, bg, fmt.Errorf("cpex: modified extensions unmarshal failed: %w", err)
		}
		typed.ModifiedExtensions = &ext
	}

	return typed, ct, bg, nil
}

// Wait blocks until all background tasks complete.
// Returns structured errors from any tasks that failed (panicked,
// errored, or timed out), plus an error if the underlying FFI call
// failed (e.g., the manager was already shutdown). On FFI failure the
// returned slice is nil.
//
// Each PluginError carries the failing plugin's name, a message, an
// optional error code, structured details, and an optional protocol
// error code (JSON-RPC / HTTP) — enough for an agent to classify
// failures without parsing strings.
//
// Holds the manager's read lock for the duration of the cgo call so
// the C handle can't be freed by a concurrent Shutdown.
func (bg *BackgroundTasks) Wait() ([]PluginError, error) {
	if bg.handle == nil {
		return nil, nil
	}
	if bg.mgr == nil {
		return nil, fmt.Errorf("BackgroundTasks.Wait: %w", ErrCpexInvalidHandle)
	}

	bg.mgr.mu.RLock()
	defer bg.mgr.mu.RUnlock()
	if bg.mgr.handle == nil {
		// Rust still owns the BackgroundTasks box. The Rust-side
		// `cpex_wait_background` consumes it even on the
		// null-mgr path (P2 #11 fix), so we must not call into
		// Rust without a live manager — the box would leak.
		// Best we can do is null our handle so the caller doesn't
		// try again, and report the error.
		bg.handle = nil
		return nil, fmt.Errorf("BackgroundTasks.Wait: %w (manager shutdown; background tasks abandoned)", ErrCpexInvalidHandle)
	}

	var errorsPtr *C.uint8_t
	var errorsLen C.int

	rc := C.cpex_wait_background(bg.mgr.handle, bg.handle, &errorsPtr, &errorsLen)
	bg.handle = nil // consumed by Rust regardless of rc (per P2 #11 fix)

	if rc != 0 {
		// Output pointers are uninitialized on rc != 0 — must NOT
		// read them. C.GoBytes(nil, 0) is safe but reading garbage
		// errorsPtr / errorsLen is UB.
		return nil, errorFromRC(int(rc), "BackgroundTasks.Wait")
	}

	errorsBytes := C.GoBytes(unsafe.Pointer(errorsPtr), errorsLen)
	C.cpex_free_bytes((*C.uint8_t)(unsafe.Pointer(errorsPtr)), errorsLen)

	var pluginErrors []PluginError
	if err := msgpack.Unmarshal(errorsBytes, &pluginErrors); err != nil {
		return nil, fmt.Errorf("BackgroundTasks.Wait: error decode failed: %w", err)
	}
	return pluginErrors, nil
}

// Close releases the background task handles without waiting.
// Tasks continue running in the Rust tokio runtime.
func (bg *BackgroundTasks) Close() {
	if bg.handle == nil {
		return
	}
	C.cpex_free_background(bg.handle)
	bg.handle = nil
}

// Close releases the Rust-owned context table.
func (ct *ContextTable) Close() {
	if ct.handle == nil {
		return
	}
	C.cpex_free_context_table(ct.handle)
	ct.handle = nil
}
