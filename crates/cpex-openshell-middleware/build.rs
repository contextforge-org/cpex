// Location: ./crates/cpex-openshell-middleware/build.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu
//
// Compiles the vendored OpenShell `SupervisorMiddleware` contract into a tonic
// server stub. The .proto is a verbatim copy of OpenShell's
// proto/supervisor_middleware.proto (package openshell.middleware.v1); vendoring
// keeps this service buildable on its own toolchain without depending on the
// OpenShell tree.

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/supervisor_middleware.proto");

    // Codegen needs `protoc` (the protobuf compiler that parses the .proto); the
    // generated code targets the prost runtime either way. We obtain protoc from
    // protoc-bin-vendored, which ships a prebuilt protoc binary plus the
    // well-known-type includes (google/protobuf/{empty,struct}.proto) the
    // contract imports — a distro protoc often omits those includes. This avoids
    // depending on a system protoc; it is not a cmake question (building protoc
    // from source, e.g. via protobuf-src, is what would pull in cmake, and it
    // produces the same generated code, so there's no reason to).
    //
    // SAFETY: build scripts run single-threaded; nothing else reads env here.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    let wkt_include = protoc_bin_vendored::include_path()?;

    let proto_root = PathBuf::from("proto");
    tonic_prost_build::configure()
        .build_server(true)
        // A client is unnecessary — OpenShell is the client — but building it is
        // cheap and lets tests exercise the service over a real channel.
        .build_client(true)
        .compile_protos(
            &[proto_root.join("supervisor_middleware.proto")],
            // Both the vendored contract's own dir and the well-known-type
            // include tree the prebuilt protoc ships.
            &[proto_root, wkt_include],
        )?;

    Ok(())
}
