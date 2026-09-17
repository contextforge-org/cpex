// Location: ./builtins/plugins/elicitation-ciba/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// cpex-plugin-elicitation-ciba — `ElicitationHandler` backed by OIDC CIBA
// (Client-Initiated Backchannel Authentication).
//
// The host registers this handler against the `elicit` hook; APL
// policies select it by name (`require_approval(manager-approver, ...)`).
// The apl-cpex bridge invokes it once per dispatch / check / validate
// across the elicitation's lifetime; this crate turns each into the
// corresponding CIBA round-trip against the configured OP (Keycloak by
// default).
//
// See the module docs for the per-operation flow:
//   * [`config`] — typed `config:` block.
//   * [`store`]  — in-flight correlation store (in-memory v1).
//   * [`approver`] — the handler + CIBA HTTP.
//   * [`factory`]  — `kind: elicitation/ciba` registration.

pub mod approver;
pub mod config;
pub mod factory;
pub mod store;

pub use approver::CibaApprover;
pub use config::{CibaConfig, ClientSecretSource};
pub use factory::{CibaApproverFactory, KIND};
pub use store::{Correlation, CorrelationStore, InMemoryCorrelationStore};
