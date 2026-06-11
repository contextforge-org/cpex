// Location: ./crates/cpex-python/build.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Build script for cpex-python PyO3 extension module.
// Ensures proper linking configuration for extension-module feature.

fn main() {
    // When building with extension-module feature, PyO3 should NOT link
    // against Python at build time. The extension will be loaded by Python
    // at runtime. This is the standard pattern for Python extension modules.
    //
    // On macOS, the linker sometimes tries to resolve Python symbols anyway,
    // causing "Undefined symbols" errors. This build script ensures the
    // extension-module feature is properly respected.
    
    #[cfg(target_os = "macos")]
    {
        // Tell cargo to pass the -undefined dynamic_lookup flag to the linker
        // This allows undefined symbols (Python API) to be resolved at runtime
        println!("cargo:rustc-cdylib-link-arg=-undefined");
        println!("cargo:rustc-cdylib-link-arg=dynamic_lookup");
    }
}

// Made with Bob
