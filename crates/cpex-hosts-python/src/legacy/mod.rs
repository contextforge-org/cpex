// Location: ./crates/cpex-hosts-python/src/legacy/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy Python plugin compatibility.
//
// Support for running existing Python plugins unchanged: the Rust host speaks
// the plugins' native bare hook names and typed payloads.

pub mod hooks;
