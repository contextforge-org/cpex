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
//   * `audit`    , a one-line audit plugin for the modules that show a
//                   side effect running before a denial (4, capstone).
//   * `approvals`, a tiny HTTP approval channel for the elicitation
//                   module, driven from a second terminal with `curl`.
//   * `ui`       , banner / outcome printing shared by every module so
//                   the terminal recordings look consistent.
//
// It also provides `install_http_transport`, the one engine setting every
// module shares: the HTTP transport the identity, delegation and approval
// builtins use to reach the tutorial IdP.

pub mod approvals;
pub mod audit;
pub mod backends;
pub mod idp;
pub mod mediate;
pub mod ui;

pub use mediate::{Caller, Outcome, mediate};

use std::sync::Arc;

use cpex::{HyperTransport, PolicyEngine};

/// Install the HTTP transport the tutorial's builtins use.
///
/// Builtins that fetch a JWKS, exchange a token, or open a CIBA request do
/// not bring their own HTTP client: the host installs one on the engine, and
/// each such plugin declares the `perform_http` capability to use it. The
/// bundled transport refuses private and loopback destinations, and the
/// tutorial IdP runs on `localhost`, so this one allows them.
///
/// NOT A PRODUCTION SETTING. Allowing private destinations lets a policy
/// document point a plugin at anything on the host's network. A production
/// host keeps the default (`cpex::install_default_http_transport`) or installs
/// its own transport with its own egress rules.
pub fn install_http_transport(engine: &Arc<PolicyEngine>) {
    cpex::host::warn_private_destinations();
    engine.set_http_transport(Arc::new(
        HyperTransport::new().with_allow_private_destinations(),
    ));
}
