// Location: ./crates/cpex-hosts-python/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// cpex-hosts-python — out-of-process host for existing Python CPEX plugins.
//
// The Rust `PluginManager` cannot run a Python plugin on its own. This crate
// is the Rust counterpart to the Python CLI's `client.py` + `venv_comm.py`:
// it builds a per-plugin virtualenv, launches the framework's `worker.py` in
// that venv as a long-lived subprocess, and speaks the same
// newline-delimited-JSON stdio protocol the Python CLI already uses. Existing
// PII filters, identity resolvers, and token delegators keep working while
// the gateway migrates to the Rust manager.
//
// # Topology
//
// The factory produces one plugin object per config entry. That object owns
// the venv manager (build + cache) and the worker client (subprocess +
// protocol), and supplies one hook adapter per declared hook:
//
// ```text
//   PluginManager
//     └── isolated_venv factory  ──> IsolatedPythonPlugin ──┬── venv manager
//                                     (initialize/shutdown) └── worker client
//           └── hook adapter (serialize, send, deserialize)      │
//                                                               ▼
//                                          worker.py subprocess in the venv
// ```
//
// The three concerns are split deliberately rather than ported as one
// one-to-one translation of `client.py`: each tests in isolation, and
// shared-package venv handling falls naturally to the venv manager.
//
// # Lifecycle
//
// Venv construction and worker launch happen in `initialize()`, which the
// manager awaits once per plugin (with rollback on failure), and teardown in
// `shutdown()`, which it calls in reverse order. Neither belongs on the
// invoke path — a cold pip install is measured in minutes.
//
// # Credentials
//
// The framework strips raw tokens at every process boundary (the token
// fields are `#[serde(skip)]`). Identity and delegation plugins genuinely
// need them, so this host adds a capability-gated wire DTO: a plugin that
// declared `read_inbound_credentials` or `read_delegated_tokens` gets a
// dedicated `credential` object on the task JSON, built by reading the
// in-memory token directly. Production credential types keep their serde
// guard and are never serialized. See the `credentials` module for the
// fail-closed rules and the residual exposure this does not close.
//
// # Extensions
//
// The capability-filtered `Extensions` the executor produced for a plugin is
// serialized onto the task, so a 3-arg `(payload, context, extensions)` hook
// sees out-of-process what it would see in-process. The plugin's returned
// extensions come back through the executor's existing copy-on-write merge,
// which enforces the mutability tiers — this host adds no tier logic. Sensitive
// headers are stripped in both directions and `raw_credentials` never rides
// this channel. See the `extensions` module.

pub mod conversion;
pub mod credentials;
pub mod error;
pub mod extensions;
pub mod factory;
pub mod legacy;
pub mod plugin;
pub mod venv;
pub mod worker;

// Test-only helpers. Also exposed behind the `testing` feature so the
// integration tests under `tests/` can use them — a `cfg(test)` module is
// invisible to a separate test binary.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use conversion::{GenericPayload, PayloadKind};
pub use credentials::CredentialDto;
pub use error::HostError;
pub use factory::{IsolatedVenvFactory, KIND};
pub use plugin::{IsolatedPythonPlugin, VenvConfig, DEFAULT_PLUGIN_DIR};
pub use venv::{CacheVerdict, EnsureOutcome, VenvManager};
pub use worker::WorkerClient;
