// Location: ./crates/apl-cedarling/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-cedarling — Cedarling-backed plugins for APL's two adjacent
// auth seams:
//
//   * [`identity`] — `IdentityResolveHandler` that validates inbound
//     JWTs through Cedarling and maps validated tokens into
//     `SubjectExtension` / `ClientExtension`. Optionally runs an
//     advisory Cedar policy check ("is this principal allowed at all")
//     during the validation pass.
//   * [`pdp`] — `PdpResolver` for `cedar:(...)` steps in APL routes.
//     Mirrors the cedar-direct resolver but uses Cedarling's policy
//     store loading + (eventually) Lock Server hooks instead of
//     in-process `cedar-policy::PolicySet`.
//
// Both modules share a single `Cedarling` instance constructed from
// the same bootstrap config — operators using one almost always want
// the other, and double-loading the policy store / JWKS would be
// wasteful.
//
// # When to reach for this crate vs alternatives
//
// - **`apl-pdp-cedar-direct`** — simpler, ~5 transitive deps,
//   policies as inline text. Use for tests, dev, or deployments
//   that don't need policy-store signing / centralized management.
// - **`apl-identity-jwt`** (future) — JWT validation via the
//   `jsonwebtoken` crate, no Cedar coupling, ~5 transitive deps.
//   Use when you want lightweight identity without policy-driven
//   identity decisions.
// - **`apl-cedarling`** (this crate) — heavy dep tree but gives you
//   signed policy stores, Cedar-driven identity decisions, and
//   (future) Lock Server fleet management. Use for production
//   deployments with centralized policy management.
//
// # Sub-step A scope
//
// Module skeletons + crate wiring only. No actual Cedarling calls.
// Existence of this crate validates the dep-resolution cost honestly
// before we commit to the implementation.

pub mod error;
pub mod identity;
pub mod pdp;

pub use error::CedarlingPluginError;
