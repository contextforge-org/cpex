// Location: ./examples/tutorial/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Shared harness for the CPEX tutorial. Each tutorial module is a binary
// under `examples/`; they all lean on this crate for:
//
//   * `backends` , fake HR / repo / email tool implementations, so a
//                   module can focus on *policy*, not on standing up a
//                   real service.
//   * `mediate`  , the one function every module calls. It wraps the
//                   CPEX dispatch loop a host owns (resolve identity →
//                   pre-invocation policy → backend → post-invocation
//                   policy) behind a single call. See its "no magic"
//                   note: this is harness code, not a CPEX API.
//   * `idp`      , mint a token from the tutorial Keycloak realm.
//   * `approvals`, a tiny HTTP approval channel for the elicitation
//                   module, driven from a second terminal with `curl`.
//   * `ui`       , banner / outcome printing shared by every module so
//                   the terminal recordings look consistent.

pub mod approvals;
pub mod backends;
pub mod idp;
pub mod mediate;
pub mod ui;

pub use mediate::{mediate, Caller, Outcome};
