// Location: ./go/cpex/apl.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// APL (Attribute Policy Language) and builtin wiring.
//
// EnableAPL registers the bundled plugin, PDP and session-store
// factories, installs the APL config visitor, the outbound HTTP
// transport, and the secret providers, via the cpex_apl_install FFI
// entry point. Call it after NewPolicyEngineDefault and before
// LoadConfig so that LoadConfig walks the config's `apl:` blocks and
// installs per-route handlers.

package cpex

import (
	"fmt"
)

/*
#include <stdint.h>

// Opaque handle, same typedef as engine.go / ffi.go. Duplicated here
// because cgo does NOT merge declarations across files' preambles; see
// the note in engine.go. Edit all copies together if the signature
// changes.
typedef void* CpexEngine;

extern int cpex_apl_install(CpexEngine engine, uint32_t flags);
*/
import "C"

// aplAllowPrivateDestinations mirrors CPEX_APL_ALLOW_PRIVATE_DESTINATIONS
// in crates/cpex-ffi/src/apl.rs.
const aplAllowPrivateDestinations uint32 = 1

// APLOption configures EnableAPL.
type APLOption func(*aplSettings)

type aplSettings struct {
	flags uint32
}

// WithPrivateDestinations lets builtins reach private, loopback and
// link-local addresses, for example a JWKS endpoint on localhost or an
// in-cluster Vault. Without it such requests are refused and builtins
// report their egress-denied codes. This is a host decision: no policy
// document can turn it on.
func WithPrivateDestinations() APLOption {
	return func(s *aplSettings) {
		s.flags |= aplAllowPrivateDestinations
	}
}

// aplFlags folds options into the cpex_apl_install flag word.
func aplFlags(opts ...APLOption) uint32 {
	var s aplSettings
	for _, opt := range opts {
		if opt != nil {
			opt(&s)
		}
	}
	return s.flags
}

// EnableAPL installs the bundled builtins on the engine: the plugin,
// PDP and session-store factories, the APL config visitor, one
// outbound HTTP transport, and the secret providers (env, file, vault),
// with Vault using the same transport.
//
// Bundled plugin kinds: identity/jwt, identity/api-key, delegator/oauth,
// elicitation/ciba. Bundled PDP kinds: cedar-direct, cel, opa. Bundled
// session store: valkey (the in-process memory store stays the default).
// Plugins that reach the network (jwks_url, OAuth, CIBA, Vault) must
// declare the `perform_http` capability.
//
// Private and loopback destinations are blocked unless the call passes
// WithPrivateDestinations.
//
// Ordering: call after NewPolicyEngineDefault and before LoadConfig.
// The one-shot NewPolicyEngine(yaml) constructor loads config during
// creation and therefore does NOT support APL; use the default-engine
// flow instead:
//
//	engine, err := NewPolicyEngineDefault()
//	if err != nil { ... }
//	engine.EnableAPL()
//	engine.LoadConfig(yaml)
//	engine.Initialize()
//
// Idempotent per engine: once a call has succeeded, later calls do
// nothing and return nil, whatever their options.
//
// On failure the returned error wraps a typed sentinel
// (ErrCpexInvalidHandle, ErrCpexInvalidInput, ErrCpexPanic).
func (m *PolicyEngine) EnableAPL(opts ...APLOption) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.handle == nil {
		return fmt.Errorf("EnableAPL: %w", ErrCpexInvalidHandle)
	}

	rc := C.cpex_apl_install(m.handle, C.uint32_t(aplFlags(opts...)))
	return errorFromRC(int(rc), "EnableAPL")
}
