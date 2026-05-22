// Location: ./crates/apl-identity-jwt/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-identity-jwt — JWT-based `IdentityResolveHandler` for APL.
//
// Validates inbound JWTs against configured trusted issuers and
// maps validated claims into the request's `IdentityPayload`
// (subject / client / raw_credentials slots). Designed as the
// lightweight identity path that pairs with `apl-cedarling`'s
// PDP role — operators wanting both run identity here, policy
// gating through `cedarling:` steps.
//
// Sub-step A scope: data shapes + module structure only. Actual
// validation logic in sub-step B; multi-issuer + key rotation in
// sub-step C; integration tests in sub-step D.
//
// # Error handling
//
// No bespoke error type. Two surfaces:
//
//   * **Build / config errors** — constructors return
//     `Result<Self, Box<PluginError>>`. Bad PEM, missing issuer
//     URL, etc. surface as `PluginError::Config { message }`.
//   * **Runtime token-rejection errors** — handler returns
//     `PluginResult::deny(PluginViolation::new(code, reason))`.
//     `code` is a stable identifier the host can map to HTTP
//     status (`auth.token_expired`, `auth.signature_invalid`,
//     `auth.untrusted_issuer`, …); `reason` is the operator-
//     readable message.
//
// # When to use this vs alternatives
//
// - **`apl-identity-jwt`** (this crate) — JWT-only flow.
//   Lightweight, ~5-15 transitive deps. The default choice for
//   "validate a Bearer token, extract identity."
// - **`apl-cedarling`** as identity (deferred) — Cedarling's API
//   doesn't expose validated entities to callers, so we deferred
//   wiring it as an IdentityResolveHandler. Use this crate for
//   validation + a `cedarling:` step early in the route policy
//   block if you want policy-driven identity gating.
// - **Custom resolver** — anyone with bespoke identity flows
//   (mTLS-only, opaque tokens with introspection, capability
//   tokens) writes their own `HookHandler<IdentityHook>`. This
//   crate's API surface is the reference shape but nothing
//   prevents other resolvers from coexisting.

pub mod claim_map;
pub mod config;
pub mod resolver;
pub mod trusted_issuer;

pub use claim_map::{ClaimMap, ClaimMapper, StandardClaimMap};
pub use config::{
    DecodingKeySource, JwtIdentityResolverConfig, TrustedIssuerConfig,
};
pub use resolver::JwtIdentityResolver;
pub use trusted_issuer::TrustedIssuer;
