// Location: ./crates/apl-delegator-biscuit/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// apl-delegator-biscuit — `TokenDelegateHandler` backed by biscuit
// capability-token attenuation.
//
// The host registers this against `token.delegate`; outbound
// forwarding plugins invoke `mgr.invoke_named::<TokenDelegateHook>(...)`
// with a `DelegationPayload` whose `bearer_token` is a base64-
// encoded biscuit. This handler parses + verifies the inbound
// biscuit against the configured root public key, appends a
// delegation block that narrows the capabilities per the route's
// requested permissions + audience + TTL, and returns the new
// base64-encoded biscuit as the `RawDelegatedToken`.
//
// # AIP Chained Mode
//
// The output of this delegator is structurally what
// `draft-prakash-aip-00` calls a "Chained Mode" token — authority
// block (the inbound) + one delegation block (our attenuation).
// Subsequent hops can each append further blocks. Completion blocks
// (post-execution audit) are a future hook family.
//
// Sub-step A scope: module structure only. Real implementation in
// sub-step B; integration tests in sub-step C.

pub mod config;
pub mod delegator;

pub use config::{BiscuitDelegatorConfig, PublicKeySource};
pub use delegator::BiscuitDelegator;
