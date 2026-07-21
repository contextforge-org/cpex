// Location: ./go/cpex/apl_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tests for APL wiring (EnableAPL). Run against the real Rust runtime
// via cgo; build the staticlib first:
//
//	cargo build --release -p cpex-ffi
//	go test -v ./...

package cpex

import (
	"errors"
	"testing"
)

// TestEnableAPLLoadsAplConfig drives the documented APL flow:
// NewPluginManagerDefault → EnableAPL → LoadConfig (APL-annotated) →
// Initialize. The bundled `audit/logger` factory must instantiate, so
// the cmf.tool_pre_invoke hook is registered after load.
func TestEnableAPLLoadsAplConfig(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.EnableAPL(); err != nil {
		t.Fatalf("EnableAPL failed: %v", err)
	}

	yaml := `
plugins:
  - name: auditor
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "plugin(auditor)"
`
	if err := mgr.LoadConfig(yaml); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if mgr.PluginCount() < 1 {
		t.Errorf("expected at least 1 plugin, got %d", mgr.PluginCount())
	}
	if !mgr.HasHooksFor("cmf.tool_pre_invoke") {
		t.Error("expected cmf.tool_pre_invoke hook registered after APL load")
	}
}

// TestEnableAPLAfterShutdown verifies the typed handle error is returned
// when EnableAPL is called on a shut-down manager.
func TestEnableAPLAfterShutdown(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	mgr.Shutdown()

	err = mgr.EnableAPL()
	if !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("expected ErrCpexInvalidHandle, got %v", err)
	}
}
