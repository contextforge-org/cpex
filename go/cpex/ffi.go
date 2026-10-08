// Location: ./go/cpex/ffi.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CGO declarations for the CPEX FFI layer.
//
// Declares the C function signatures from libcpex_ffi. These are
// opaque handles. Go callers use the PolicyEngine wrapper in
// engine.go rather than calling these directly.

package cpex

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lcpex_ffi
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
// The Rust staticlib needs libm, libdl and libpthread on Linux (rustc's
// native-static-libs). glibc 2.34+ folds dl and pthread into libc, but
// older glibc and libm still need them named; musl ships stubs.
#cgo linux LDFLAGS: -lm -ldl -lpthread

#include <stdint.h>
#include <stdlib.h>

// Opaque handles
typedef void* CpexEngine;
typedef void* CpexContextTable;
typedef void* CpexBackgroundTasks;

// ABI version
uint32_t cpex_ffi_abi_version(void);

// Runtime configuration
int cpex_configure_runtime(int worker_threads);

// Engine lifecycle
CpexEngine cpex_engine_new(const char* config_yaml, int config_len);
CpexEngine cpex_engine_new_default();
int cpex_load_config(CpexEngine engine, const char* config_yaml, int config_len);
int cpex_initialize(CpexEngine engine);
void cpex_shutdown(CpexEngine engine);

// Query
int cpex_has_hooks_for(CpexEngine engine, const char* hook_name, int hook_len);
int cpex_plugin_count(CpexEngine engine);
int cpex_is_initialized(CpexEngine engine);
int cpex_plugin_names(CpexEngine engine, uint8_t** names_msgpack_out, int* names_len_out);

// Builtins, transport and secret providers
int cpex_apl_install(CpexEngine engine, uint32_t flags);

// Secrets
int cpex_refresh_secrets(CpexEngine engine, uint8_t** report_msgpack_out, int* report_len_out);
int cpex_secrets_last_success(CpexEngine engine, const char* provider, int provider_len, int64_t* unix_ms_out);

// Invoke
int cpex_invoke(
    CpexEngine engine,
    const char* hook_name, int hook_len,
    uint8_t payload_type,
    const uint8_t* payload_msgpack, int payload_len,
    const uint8_t* extensions_msgpack, int extensions_len,
    CpexContextTable context_table,
    uint8_t** result_msgpack_out, int* result_len_out,
    CpexContextTable* context_table_out,
    CpexBackgroundTasks* bg_handle_out
);
int cpex_invoke_resolved(
    CpexEngine engine,
    const uint8_t* identity_msgpack, int identity_len,
    const char* hook_name, int hook_len,
    uint8_t payload_type,
    const uint8_t* payload_msgpack, int payload_len,
    const uint8_t* extensions_msgpack, int extensions_len,
    CpexContextTable context_table,
    uint8_t** result_msgpack_out, int* result_len_out,
    CpexContextTable* context_table_out,
    CpexBackgroundTasks* bg_handle_out
);

// Background tasks
int cpex_wait_background(
    CpexEngine engine,
    CpexBackgroundTasks bg_handle,
    uint8_t** errors_msgpack_out, int* errors_len_out
);
void cpex_free_background(CpexBackgroundTasks bg_handle);

// Memory
void cpex_free_context_table(CpexContextTable ct);
void cpex_free_bytes(uint8_t* ptr, int len);
*/
import "C"
