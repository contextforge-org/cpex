// Location: ./go/cpex/ffi.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CGO declarations for the CPEX FFI layer.
//
// Declares the C function signatures from libcpex_ffi. These are
// opaque handles — Go callers use the PluginManager wrapper in
// manager.go rather than calling these directly.

package cpex

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lcpex_ffi

#include <stdint.h>
#include <stdlib.h>

// Opaque handles
typedef void* CpexManager;
typedef void* CpexContextTable;
typedef void* CpexBackgroundTasks;

// Runtime configuration
int cpex_configure_runtime(int worker_threads);

// Manager lifecycle
CpexManager cpex_manager_new(const char* config_yaml, int config_len);
CpexManager cpex_manager_new_default();
int cpex_load_config(CpexManager mgr, const char* config_yaml, int config_len);
int cpex_initialize(CpexManager mgr);
void cpex_shutdown(CpexManager mgr);

// Query
int cpex_has_hooks_for(CpexManager mgr, const char* hook_name, int hook_len);
int cpex_plugin_count(CpexManager mgr);
int cpex_is_initialized(CpexManager mgr);
int cpex_plugin_names(CpexManager mgr, uint8_t** names_msgpack_out, int* names_len_out);

// Invoke
int cpex_invoke(
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

// Background tasks
int cpex_wait_background(
    CpexManager mgr,
    CpexBackgroundTasks bg_handle,
    uint8_t** errors_msgpack_out, int* errors_len_out
);
void cpex_free_background(CpexBackgroundTasks bg_handle);

// Memory
void cpex_free_context_table(CpexContextTable ct);
void cpex_free_bytes(uint8_t* ptr, int len);
*/
import "C"
