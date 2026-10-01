// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Reference demo plugins — feature-gated.
// Browse these for patterns; edit src/plugin.rs for your own plugin.
//
// Build a demo:  make build-demo DEMO=noop
// Build all:     make build-demos

#[cfg(feature = "identity-checker")]
pub mod identity_checker;

#[cfg(feature = "header-injector")]
pub mod header_injector;

#[cfg(feature = "audit-logger")]
pub mod audit_logger;

#[cfg(feature = "token-attenuator")]
pub mod token_attenuator;

#[cfg(feature = "noop")]
pub mod noop;


#[cfg(feature = "tool-invoke-checker")]
pub mod tool_invoke_checker;

#[cfg(feature = "compute-bench")]
pub mod compute_bench;

#[cfg(feature = "pii-guard")]
pub mod pii_guard;

#[cfg(feature = "audit-logger-custom")]
pub mod audit_logger_custom;

#[cfg(feature = "remote-authz")]
pub mod remote_authz;

#[cfg(feature = "fs-sandbox-demo")]
pub mod fs_sandbox_demo;

#[cfg(feature = "env-sandbox-demo")]
pub mod env_sandbox_demo;

#[cfg(feature = "resource-sandbox-demo")]
pub mod resource_sandbox_demo;

#[cfg(feature = "net-sandbox-demo")]
pub mod net_sandbox_demo;
