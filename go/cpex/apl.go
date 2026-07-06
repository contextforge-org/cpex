// Location: ./go/cpex/apl.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// APL (Authorization Policy Language) wiring.
//
// EnableAPL registers the bundled APL plugin/PDP factories and installs
// the APL config visitor on the manager via the cpex_apl_install FFI
// entry point. Call it after NewPluginManagerDefault and before
// LoadConfig so that LoadConfig walks the config's `apl:` blocks and
// installs per-route handlers.

package cpex

import (
	"fmt"
)

/*
#include <stdint.h>

// Opaque handle — same typedef as manager.go / ffi.go. Duplicated here
// because cgo does NOT merge declarations across files' preambles; see
// the note in manager.go. Edit all copies together if the signature
// changes.
typedef void* CpexManager;

extern int cpex_apl_install(CpexManager mgr);
*/
import "C"

// EnableAPL registers the bundled APL plugin and PDP factories and
// installs the APL config visitor on the manager (in-process defaults:
// memory session store, default baseline capabilities).
//
// Bundled plugin kinds: validator/pii-scan, audit/logger, identity/jwt,
// delegator/oauth. Bundled PDP kind: cedar-direct.
//
// Ordering: call after NewPluginManagerDefault and before LoadConfig.
// The one-shot NewPluginManager(yaml) constructor loads config during
// creation and therefore does NOT support APL — use the default-manager
// flow instead:
//
//	mgr, _ := NewPluginManagerDefault()
//	mgr.EnableAPL()
//	mgr.LoadConfig(yaml)
//	mgr.Initialize()
//
// On failure the returned error wraps a typed sentinel
// (ErrCpexInvalidHandle, ErrCpexPanic).
func (m *PluginManager) EnableAPL() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return fmt.Errorf("EnableAPL: %w", ErrCpexInvalidHandle)
	}

	rc := C.cpex_apl_install(m.handle)
	return errorFromRC(int(rc), "EnableAPL")
}
