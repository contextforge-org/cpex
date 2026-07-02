// Location: ./bindings/python/build.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// macOS linker flag for plain `cargo build -p cpex-python` (without maturin).
//
// When built outside maturin the `extension-module` feature is absent, which
// means libpython isn't linked. On macOS the dynamic linker still rejects an
// undefined symbol at load time, so we emit `-undefined dynamic_lookup` to
// defer Python symbol resolution to the final host executable. This mirrors
// the approach used by maturin itself.
//
// Under maturin `CARGO_FEATURE_EXTENSION_MODULE` is set, so we skip the flag
// to avoid a duplicate that maturin already injects (KD3).

fn main() {
    #[cfg(target_os = "macos")]
    if std::env::var("CARGO_FEATURE_EXTENSION_MODULE").is_err() {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
