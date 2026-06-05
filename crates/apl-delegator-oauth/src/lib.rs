// Location: ./crates/apl-delegator-oauth/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-delegator-oauth — `TokenDelegateHandler` backed by RFC 8693
// OAuth 2.0 Token Exchange.
//
// The host registers this handler against `token.delegate`; outbound
// forwarding plugins invoke `mgr.invoke_named::<TokenDelegateHook>(...)`
// with a `DelegationPayload` (caller's bearer token + target
// audience + required scopes); this handler POSTs to the configured
// OAuth server's token endpoint with `grant_type=urn:ietf:params:
// oauth:grant-type:token-exchange` and the appropriate
// `subject_token` / `audience` / `scope` parameters; the response's
// `access_token` becomes the `RawDelegatedToken` the framework
// stashes under `Extensions.raw_credentials.delegated_tokens`.
//
// Sub-step A scope: data shapes + module structure only. Actual
// HTTP exchange logic in sub-step B; mock-IdP integration tests in
// sub-step C.

pub mod config;
pub mod delegator;
pub mod factory;

pub use config::{ClientSecretSource, OAuthDelegatorConfig};
pub use delegator::OAuthDelegator;
pub use factory::{OAuthDelegatorFactory, KIND};
