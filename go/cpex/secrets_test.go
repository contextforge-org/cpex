// Location: ./go/cpex/secrets_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

package cpex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An engine with no secrets block returns an empty report.
func TestRefreshSecretsWithNoSecretsIsEmpty(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	defer eng.Shutdown()
	if err := eng.EnableAPL(); err != nil {
		t.Fatalf("EnableAPL failed: %v", err)
	}
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	report, err := eng.RefreshSecrets()
	if err != nil {
		t.Fatalf("RefreshSecrets failed: %v", err)
	}
	if len(report.Updated) != 0 || report.Unchanged != 0 || len(report.Failed) != 0 {
		t.Errorf("expected an empty report, got %+v", report)
	}
}

// With no declared provider there is no last success.
func TestSecretsLastSuccessUnknownProvider(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	defer eng.Shutdown()
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	at, ok, err := eng.SecretsLastSuccess("vault")
	if err != nil {
		t.Fatalf("SecretsLastSuccess failed: %v", err)
	}
	if ok || !at.IsZero() {
		t.Errorf("expected no last success, got ok=%v at=%v", ok, at)
	}
}

func TestSecretsAfterShutdownReturnTypedError(t *testing.T) {
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault failed: %v", err)
	}
	eng.Shutdown()

	if _, err := eng.RefreshSecrets(); !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("RefreshSecrets: expected ErrCpexInvalidHandle, got %v", err)
	}
	if _, _, err := eng.SecretsLastSuccess("env"); !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("SecretsLastSuccess: expected ErrCpexInvalidHandle, got %v", err)
	}
}

// A `kind: file` provider reports a rotation as an update and a missing
// file as a failure, and its last success tracks the latest refresh.
func TestRefreshSecretsReportsUpdatesAndFailures(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "api_key")
	if err := os.WriteFile(secretFile, []byte("first"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	yaml := "engine_settings:\n  dispatch: hooks\n" +
		"secrets:\n" +
		"  providers:\n    local:\n      kind: file\n" +
		"  values:\n    api_key:\n      provider: local\n      ref: " + secretFile + "\n"
	eng := accEngine(t, yaml)

	first, ok, err := eng.SecretsLastSuccess("local")
	if err != nil {
		t.Fatalf("SecretsLastSuccess failed: %v", err)
	}
	if !ok || first.IsZero() {
		t.Fatalf("expected a last success after Initialize, got ok=%v at=%v", ok, first)
	}

	report, err := eng.RefreshSecrets()
	if err != nil {
		t.Fatalf("RefreshSecrets failed: %v", err)
	}
	if len(report.Updated) != 0 || report.Unchanged != 1 || len(report.Failed) != 0 {
		t.Errorf("expected one unchanged secret, got %+v", report)
	}

	if err := os.WriteFile(secretFile, []byte("second"), 0o600); err != nil {
		t.Fatalf("rewrite secret: %v", err)
	}
	report, err = eng.RefreshSecrets()
	if err != nil {
		t.Fatalf("RefreshSecrets failed: %v", err)
	}
	if len(report.Updated) != 1 || report.Updated[0] != "api_key" || report.Unchanged != 0 || len(report.Failed) != 0 {
		t.Errorf("expected api_key updated, got %+v", report)
	}
	again, ok, err := eng.SecretsLastSuccess("local")
	if err != nil {
		t.Fatalf("SecretsLastSuccess failed: %v", err)
	}
	if !ok || again.Before(first) {
		t.Errorf("expected last success at or after %v, got ok=%v at=%v", first, ok, again)
	}

	if err := os.Remove(secretFile); err != nil {
		t.Fatalf("remove secret: %v", err)
	}
	report, err = eng.RefreshSecrets()
	if err != nil {
		t.Fatalf("RefreshSecrets failed: %v", err)
	}
	if len(report.Updated) != 0 || report.Unchanged != 0 || len(report.Failed) != 1 {
		t.Fatalf("expected one failure, got %+v", report)
	}
	failure := report.Failed[0]
	if failure.Secret != "api_key" || failure.Provider != "local" || failure.Kind != "not_found" {
		t.Errorf("unexpected failure fields: %+v", failure)
	}
	if failure.Message == "" {
		t.Error("expected a failure message")
	}
	if strings.Contains(failure.Message, "second") {
		t.Error("the failure message must not carry the secret")
	}
	if at, ok, err := eng.SecretsLastSuccess("local"); err != nil || ok || !at.IsZero() {
		t.Errorf("expected a failed refresh to clear last success, got ok=%v at=%v err=%v", ok, at, err)
	}
}
