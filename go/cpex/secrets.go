// Location: ./go/cpex/secrets.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Secret refresh and health.
//
// The engine resolves every declared secret once, at Initialize, and
// never re-reads on its own. The host decides when: call RefreshSecrets
// on a schedule to re-read values (renewing a Vault token when due), and
// SecretsLastSuccess to alarm on a stale credential.

package cpex

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/vmihailenco/msgpack/v5"
)

/*
#include <stdint.h>
#include <stdlib.h>

// Duplicated from the ffi.go preamble; see the note in engine.go about
// cgo not merging declarations across files.
typedef void* CpexEngine;

extern int cpex_refresh_secrets(CpexEngine engine, uint8_t** report_msgpack_out, int* report_len_out);
extern int cpex_secrets_last_success(CpexEngine engine, const char* provider, int provider_len, int64_t* unix_ms_out);
extern void cpex_free_bytes(uint8_t* ptr, int len);
*/
import "C"

// RefreshReport is the outcome of one RefreshSecrets call.
type RefreshReport struct {
	// Updated names the values whose bytes changed.
	Updated []string `msgpack:"updated"`
	// Unchanged counts the values that were re-read and found unchanged.
	Unchanged uint64 `msgpack:"unchanged"`
	// Failed lists the values that could not be re-read. Each keeps its
	// last-good value.
	Failed []RefreshFailure `msgpack:"failed"`
}

// RefreshFailure is one value that failed to re-read.
type RefreshFailure struct {
	// Secret is the declared value name.
	Secret string `msgpack:"secret"`
	// Provider is the provider the value is bound to.
	Provider string `msgpack:"provider"`
	// Kind is the failure class: "config", "reference", "not_found",
	// "malformed", "backend", or "other".
	Kind string `msgpack:"kind"`
	// Message is what the provider reported. It never contains the secret.
	Message string `msgpack:"message"`
}

// RefreshSecrets re-reads every declared secret and reports what changed
// and what failed. A value that fails to re-read is listed in Failed and
// is not an error return. An engine with no `secrets:` block, or one not
// yet initialized, returns an empty report.
//
// On failure the returned error wraps a typed sentinel
// (ErrCpexInvalidHandle, ErrCpexSerialize, ErrCpexTimeout, ErrCpexPanic).
func (m *PolicyEngine) RefreshSecrets() (*RefreshReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return nil, fmt.Errorf("RefreshSecrets: %w", ErrCpexInvalidHandle)
	}

	var reportPtr *C.uint8_t
	var reportLen C.int
	rc := C.cpex_refresh_secrets(m.handle, &reportPtr, &reportLen)
	if rc != 0 {
		return nil, errorFromRC(int(rc), "RefreshSecrets")
	}

	bytes := C.GoBytes(unsafe.Pointer(reportPtr), reportLen)
	C.cpex_free_bytes(reportPtr, reportLen)

	var report RefreshReport
	if err := msgpack.Unmarshal(bytes, &report); err != nil {
		return nil, fmt.Errorf("RefreshSecrets: decode failed: %w", err)
	}
	return &report, nil
}

// SecretsLastSuccess reports when provider last re-read all of its
// values without a failure. Initialization counts as the first success.
//
// ok is false, and the time is zero, when there is no such moment: the
// provider has never refreshed successfully, the name is not a declared
// provider, or secrets are not resolved yet. Failed refreshes retain the
// last successful time; inspect RefreshReport.Failed to detect an outage.
//
// On failure the returned error wraps a typed sentinel
// (ErrCpexInvalidHandle, ErrCpexInvalidInput).
func (m *PolicyEngine) SecretsLastSuccess(provider string) (at time.Time, ok bool, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return time.Time{}, false, fmt.Errorf("SecretsLastSuccess: %w", ErrCpexInvalidHandle)
	}

	cName := C.CString(provider)
	defer C.free(unsafe.Pointer(cName))

	var unixMs C.int64_t
	rc := C.cpex_secrets_last_success(m.handle, cName, C.int(len(provider)), &unixMs)
	if rc != 0 {
		return time.Time{}, false, errorFromRC(int(rc), "SecretsLastSuccess")
	}
	if unixMs == 0 {
		return time.Time{}, false, nil
	}
	return time.UnixMilli(int64(unixMs)), true, nil
}
