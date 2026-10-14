// Location: ./go/cpex/abi_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

package cpex

import (
	"fmt"
	"strings"
	"testing"
)

func TestCheckFFIABIVersionAcceptsExpected(t *testing.T) {
	if err := checkFFIABIVersion(expectedFFIABIVersion); err != nil {
		t.Errorf("expected no error for ABI %d, got %v", expectedFFIABIVersion, err)
	}
}

// A library built at an older ABI is rejected with a message naming
// both versions.
func TestCheckFFIABIVersionRejectsMismatch(t *testing.T) {
	err := checkFFIABIVersion(2)
	if err == nil {
		t.Fatal("expected an error for ABI 2")
	}
	msg := err.Error()
	for _, want := range []string{
		"ABI version mismatch",
		fmt.Sprintf("expects %d", expectedFFIABIVersion),
		"reports 2",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
}

func TestLinkedLibraryReportsABI3(t *testing.T) {
	if got := linkedFFIABIVersion(); got != 3 {
		t.Errorf("expected linked libcpex_ffi ABI 3, got %d", got)
	}
	if expectedFFIABIVersion != 3 {
		t.Errorf("expected binding ABI 3, got %d", expectedFFIABIVersion)
	}
}
