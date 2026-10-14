// Location: ./go/cpex/abi.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// FFI ABI version check.
//
// On package init, calls cpex_ffi_abi_version() and panics if the
// linked libcpex_ffi reports an ABI version different from what this
// Go binding was generated against. A mismatch means the C surface
// the bindings expect is not the one libcpex_ffi exposes, so every
// other cgo call in this package would have undefined behavior.
// Failing loudly at init is preferred over silent corruption later.
//
// Bumping expectedFFIABIVersion is required (and only required) when
// the Rust crate bumps FFI_ABI_VERSION. See crates/cpex-ffi/src/lib.rs
// "FFI ABI Version" section for what counts as a breaking change.

package cpex

/*
#include <stdint.h>

// Duplicated from the ffi.go / engine.go preambles; see the note in
// engine.go about cgo not merging declarations across files.
extern uint32_t cpex_ffi_abi_version(void);
*/
import "C"

import "fmt"

// expectedFFIABIVersion is the FFI_ABI_VERSION integer this binding
// was generated against. Bump in lockstep with the Rust crate's
// FFI_ABI_VERSION whenever the C surface changes in a breaking way.
const expectedFFIABIVersion uint32 = 3

// checkFFIABIVersion returns an error when the ABI version reported by
// the linked libcpex_ffi differs from the one this binding expects.
func checkFFIABIVersion(actual uint32) error {
	if actual == expectedFFIABIVersion {
		return nil
	}
	return fmt.Errorf(
		"cpex: FFI ABI version mismatch: Go binding expects %d, "+
			"linked libcpex_ffi reports %d. Upgrade github.com/"+
			"contextforge-org/cpex/go/cpex "+
			"to a version generated against libcpex_ffi ABI %d, "+
			"or rebuild libcpex_ffi from a CPEX commit whose "+
			"FFI_ABI_VERSION is %d",
		expectedFFIABIVersion, actual, actual, expectedFFIABIVersion,
	)
}

// linkedFFIABIVersion is the ABI version the linked libcpex_ffi reports.
func linkedFFIABIVersion() uint32 {
	return uint32(C.cpex_ffi_abi_version())
}

func init() {
	// Intentional panic: init() has no error return, and a mismatched
	// ABI means every cgo call in this package is already unsound.
	// There is no error value we could hand back to a caller.
	if err := checkFFIABIVersion(linkedFFIABIVersion()); err != nil {
		panic(err.Error())
	}
}
