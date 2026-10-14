// Location: ./go/cpex/legacy_hooks_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Hook names removed in 0.3 are refused at invoke time. Such a name reaches
// no handler, so dispatching it would come back allowed with no policy
// evaluated. Run against the real Rust runtime via cgo; build the staticlib
// first:
//
//	cargo build --release -p cpex-ffi
//	go test -v ./...

package cpex

import (
	"errors"
	"testing"
)

// removedHooks pairs each removed name with its replacement, matching
// cpex::host::REMOVED_HOOKS in the Rust facade.
var removedHooks = map[string]string{
	"tool_pre_invoke":       "cmf.tool_pre_invoke",
	"tool_post_invoke":      "cmf.tool_post_invoke",
	"prompt_pre_fetch":      "cmf.prompt_pre_invoke",
	"cmf.prompt_pre_fetch":  "cmf.prompt_pre_invoke",
	"prompt_post_fetch":     "cmf.prompt_post_invoke",
	"cmf.prompt_post_fetch": "cmf.prompt_post_invoke",
	"resource_pre_fetch":    "cmf.resource_pre_fetch",
	"resource_post_fetch":   "cmf.resource_post_fetch",
	"identity_resolve":      "identity.resolve",
	"token_delegate":        "token.delegate",
	"cmf.http_request":      "http.request",
	"cmf.http_response":     "http.response",
}

func newLegacyHookEngine(t *testing.T) *PolicyEngine {
	t.Helper()
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	if err := eng.EnableAPL(); err != nil {
		t.Fatalf("EnableAPL failed: %v", err)
	}
	if err := eng.LoadConfig("engine_settings:\n  dispatch: hooks\nplugins: []\n"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	return eng
}

// TestInvokeByNameRejectsRemovedHooks: every removed name fails with
// ErrCpexInvalidInput instead of an allowed result.
func TestInvokeByNameRejectsRemovedHooks(t *testing.T) {
	eng := newLegacyHookEngine(t)
	defer eng.Shutdown()

	for removed := range removedHooks {
		res, _, _, err := eng.InvokeByName(removed, PayloadGeneric, map[string]any{}, nil, nil)
		if !errors.Is(err, ErrCpexInvalidInput) {
			t.Errorf("InvokeByName(%q): want ErrCpexInvalidInput, got result %+v, err %v", removed, res, err)
		}
	}
}

// TestInvokeResolvedRejectsRemovedHooks: the fused identity path refuses
// the same names.
func TestInvokeResolvedRejectsRemovedHooks(t *testing.T) {
	eng := newLegacyHookEngine(t)
	defer eng.Shutdown()

	identity := NewIdentityPayload(TokenSourceBearer, map[string]string{"authorization": "Bearer x"})
	for removed := range removedHooks {
		res, _, _, err := eng.InvokeResolved(identity, removed, PayloadGeneric, map[string]any{}, nil, nil)
		if !errors.Is(err, ErrCpexInvalidInput) {
			t.Errorf("InvokeResolved(%q): want ErrCpexInvalidInput, got result %+v, err %v", removed, res, err)
		}
	}
}

// TestInvokeByNameAcceptsReplacementHooks: the replacement names still
// dispatch; with nothing registered they allow.
func TestInvokeByNameAcceptsReplacementHooks(t *testing.T) {
	eng := newLegacyHookEngine(t)
	defer eng.Shutdown()

	for _, replacement := range removedHooks {
		res, ct, bg, err := eng.InvokeByName(replacement, PayloadGeneric, map[string]any{}, nil, nil)
		if err != nil {
			t.Errorf("InvokeByName(%q): unexpected error %v", replacement, err)
			continue
		}
		if !res.ContinueProcessing {
			t.Errorf("InvokeByName(%q): want allow, got %+v", replacement, res)
		}
		ct.Close()
		bg.Close()
	}
}
