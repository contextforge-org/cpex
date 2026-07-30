// Location: ./crates/cpex-openshell-middleware/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu

//! CPEX as a remote OpenShell supervisor middleware.
//!
//! This library exposes the gRPC service and its supporting adapter/config/
//! runtime modules so integration tests can drive them directly. The `main`
//! binary is a thin CLI wrapper around [`serve`].

pub mod adapter;
pub mod config;
pub mod proto;
pub mod runtime;
pub mod service;

pub use service::{CpexMiddlewareService, GRPC_MESSAGE_BYTES};
