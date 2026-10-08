// Location: ./go/cpex/secrets_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

package cpex

import (
	"errors"
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
