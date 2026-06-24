// Location: ./builtins/session/valkey/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// cpex-session-valkey — a Valkey-backed `apl_cpex::SessionStore` for
// distributed, cross-restart persistence of session security labels.
//
// # Where this sits
//
//   apl-cpex (SessionStore trait, SessionStoreFactory)
//        ▲
//        │ implements
//   cpex-session-valkey  ──uses──▶  redis-rs + deadpool-redis (rustls)
//
// The host registers `ValkeySessionStoreFactory` via
// `AplOptions.session_store_factories`; a `global.apl.session_store:
// { kind: valkey, ... }` block then selects it during config load. When
// no such block is present, apl-cpex keeps its default in-process
// `MemorySessionStore`, so this crate is entirely opt-in.
//
// # Design invariants (carried from the requirements/plan)
//
//   - Fail-closed: any backend error (unreachable, timeout, undecodable)
//     becomes `SessionStoreError`; only a confirmed key-miss is empty.
//   - Atomic union: `append_labels` is a single server-side `SADD`.
//   - Primary-only: a single endpoint, no replica read-splitting.
//   - TLS required off-localhost; `noeviction` is an operator runbook
//     concern the client can only warn about.
//
// The connection layer is kept internal (no public reusable API): the
// planned OAuth token cache is the trigger to extract a shared layer
// later, shaped by two real consumers.

mod config;
mod connection;
mod error;
mod factory;
mod store;

pub use config::ValkeyConfig;
pub use error::BuildError;
pub use factory::{ValkeySessionStoreFactory, KIND};
pub use store::ValkeySessionStore;
