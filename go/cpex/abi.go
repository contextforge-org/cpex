// Location: ./go/cpex/abi.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// FFI ABI version check.
//
// On package init, calls cpex_ffi_abi_version() and panics if the
// linked libcpex_ffi reports an ABI version different from what this
// Go binding was generated against. A mismatch means the C surface
// the bindings expect is not the one libcpex_ffi exposes — every
// other cgo call in this package would have undefined behavior, so
// failing loud at init is preferred over silent corruption later.
//
// Bumping expectedFFIABIVersion is required (and only required) when
// the Rust crate bumps FFI_ABI_VERSION. See crates/cpex-ffi/src/lib.rs
// "FFI ABI Version" section for what counts as a breaking change.

package cpex

/*
#include <stdint.h>

// Duplicated from ffi.go / manager.go preambles — see the note in
// manager.go about cgo not merging declarations across files.
extern uint32_t cpex_ffi_abi_version(void);
*/
import "C"

import "fmt"

// expectedFFIABIVersion is the FFI_ABI_VERSION integer this binding
// was generated against. Bump in lockstep with the Rust crate's
// FFI_ABI_VERSION whenever the C surface changes in a breaking way.
const expectedFFIABIVersion uint32 = 1

func init() {
	actual := uint32(C.cpex_ffi_abi_version())
	if actual != expectedFFIABIVersion {
		panic(fmt.Sprintf(
			"cpex: FFI ABI version mismatch — Go binding expects %d, "+
				"linked libcpex_ffi reports %d. Upgrade github.com/"+
				"contextforge-org/contextforge-plugins-framework/go/cpex "+
				"to a version generated against libcpex_ffi ABI %d, "+
				"or rebuild libcpex_ffi from a CPEX commit whose "+
				"FFI_ABI_VERSION is %d.",
			expectedFFIABIVersion, actual, actual, expectedFFIABIVersion,
		))
	}
}
