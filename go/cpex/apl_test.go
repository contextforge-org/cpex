// Location: ./go/cpex/apl_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tests for builtin wiring (EnableAPL). Run against the real Rust
// runtime via cgo; build the staticlib first:
//
//	cargo build --release -p cpex-ffi
//	go test -v ./...

package cpex

import (
	"errors"
	"testing"
)

// aplJWTConfig uses the shipped identity/jwt builtin. The JWKS URL
// points at a closed local port: key fetch soft-fails at Initialize, so
// the config loads and initializes without a network.
const aplJWTConfig = `
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
`

// TestEnableAPLLoadsAplConfig drives the documented APL flow:
// NewPolicyEngineDefault, EnableAPL, LoadConfig (APL-annotated),
// Initialize. The bundled identity/jwt factory must instantiate, and
// the route's policy handler must sit on cmf.tool_pre_invoke.
func TestEnableAPLLoadsAplConfig(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	defer eng.Shutdown()

	if err := eng.EnableAPL(); err != nil {
		t.Fatalf("EnableAPL failed: %v", err)
	}
	if err := eng.LoadConfig(aplJWTConfig); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if got := eng.PluginCount(); got != 1 {
		t.Errorf("expected 1 plugin, got %d", got)
	}
	if !eng.HasHooksFor("identity.resolve") {
		t.Error("expected identity.resolve hook registered")
	}
	if !eng.HasHooksFor("cmf.tool_pre_invoke") {
		t.Error("expected cmf.tool_pre_invoke hook registered after APL load")
	}
}

// TestEnableAPLWithPrivateDestinations checks the option is accepted by
// the FFI (an unknown flag bit would be rejected as invalid input) and
// the engine still loads and initializes.
func TestEnableAPLWithPrivateDestinations(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	defer eng.Shutdown()

	if err := eng.EnableAPL(WithPrivateDestinations()); err != nil {
		t.Fatalf("EnableAPL(WithPrivateDestinations()) failed: %v", err)
	}
	if err := eng.LoadConfig(aplJWTConfig); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
}

func TestAPLFlags(t *testing.T) {
	if got := aplFlags(); got != 0 {
		t.Errorf("no options: expected flags 0, got %#x", got)
	}
	if got := aplFlags(WithPrivateDestinations()); got != aplAllowPrivateDestinations {
		t.Errorf("WithPrivateDestinations: expected flags %#x, got %#x", aplAllowPrivateDestinations, got)
	}
	if got := aplFlags(WithPrivateDestinations(), WithPrivateDestinations(), nil); got != aplAllowPrivateDestinations {
		t.Errorf("repeated and nil options: expected flags %#x, got %#x", aplAllowPrivateDestinations, got)
	}
}

// TestEnableAPLIsIdempotent verifies a second call is a no-op: the
// config still loads with a single plugin.
func TestEnableAPLIsIdempotent(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	defer eng.Shutdown()

	if err := eng.EnableAPL(); err != nil {
		t.Fatalf("first EnableAPL failed: %v", err)
	}
	if err := eng.EnableAPL(WithPrivateDestinations()); err != nil {
		t.Fatalf("second EnableAPL failed: %v", err)
	}
	if err := eng.LoadConfig(aplJWTConfig); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if got := eng.PluginCount(); got != 1 {
		t.Errorf("expected 1 plugin, got %d", got)
	}
}

// TestEnableAPLAfterShutdown verifies the typed handle error is returned
// when EnableAPL is called on a shut-down engine.
func TestEnableAPLAfterShutdown(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	eng.Shutdown()

	err = eng.EnableAPL()
	if !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("expected ErrCpexInvalidHandle, got %v", err)
	}
}

// TestPolicyEngineLifecycleInvokesToolPreInvoke covers the common host
// flow end to end: create, load a policy, invoke cmf.tool_pre_invoke,
// shut down. One route denies, another allows.
func TestPolicyEngineLifecycleInvokesToolPreInvoke(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	defer eng.Shutdown()

	if err := eng.EnableAPL(); err != nil {
		t.Fatalf("EnableAPL failed: %v", err)
	}
	yaml := `
routes:
  - tool: delete_repo
    authorization:
      pre_invocation:
        - "deny('deleting repositories is blocked', 'demo.delete_blocked')"
  - tool: get_weather
    authorization:
      pre_invocation:
        - "allow"
`
	if err := eng.LoadConfig(yaml); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if !eng.HasHooksFor("cmf.tool_pre_invoke") {
		t.Fatal("expected cmf.tool_pre_invoke hook registered")
	}

	invoke := func(tool string) *TypedPipelineResult[MessagePayload] {
		t.Helper()
		payload := MessagePayload{Message: NewMessage("assistant",
			NewToolCallPart(ToolCall{ToolCallID: "tc-1", Name: tool}),
		)}
		ext := &Extensions{Meta: &MetaExtension{EntityType: "tool", EntityName: tool}}
		result, ct, bg, err := Invoke[MessagePayload](
			eng, "cmf.tool_pre_invoke", PayloadCMFMessage, payload, ext, nil,
		)
		if err != nil {
			t.Fatalf("Invoke(%s) failed: %v", tool, err)
		}
		bg.Close()
		ct.Close()
		return result
	}

	denied := invoke("delete_repo")
	if !denied.IsDenied() {
		t.Fatal("expected delete_repo to be denied")
	}
	if denied.Violation.Code != "demo.delete_blocked" {
		t.Errorf("expected violation code demo.delete_blocked, got %q", denied.Violation.Code)
	}

	if allowed := invoke("get_weather"); allowed.IsDenied() {
		t.Errorf("expected get_weather to be allowed, got violation %+v", allowed.Violation)
	}

	eng.Shutdown()
	if eng.IsInitialized() {
		t.Error("expected engine not initialized after Shutdown")
	}
}
