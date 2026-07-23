// Location: ./crates/cpex-hosts-python/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// cpex-hosts-python — subprocess-isolated Python plugin adapter.
//
// Lets the Rust PluginManager load Python plugin classes through a
// subprocess-isolated virtual environment. Plugin operators declare
// `kind: "isolated_venv"` and `config: class_name: module.ClassName` in YAML; the Rust
// runtime creates and manages the venv, spawns worker.py, and drives
// it via the JSON-lines stdin/stdout protocol.

pub mod isolated;
pub mod legacy;

pub use isolated::{HookPayloadRegistry, IsolatedPythonPluginAdapterFactory, KIND};
