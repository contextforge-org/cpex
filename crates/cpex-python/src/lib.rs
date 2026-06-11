// Location: ./crates/cpex-python/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX Python bindings — PyO3 extension module.
//
// Provides native Python API for the CPEX plugin runtime with no
// serialization overhead. Python code imports `cpex._native` and
// gets a drop-in replacement for `cpex.framework.manager.PluginManager`.

use pyo3::prelude::*;

mod conversions;
mod error;
mod manager;
mod payload_registry;
mod types;

pub use error::*;
pub use manager::*;
pub use types::*;

/// CPEX native Python extension module.
///
/// Exports:
/// - `PluginManager`: Rust-backed plugin manager with 5-phase execution
///
/// # Usage
///
/// ```python
/// from cpex._native import PluginManager
///
/// # Sync construction - loads config
/// manager = PluginManager("config.yaml")
///
/// # Async initialization - calls plugin.initialize()
/// await manager.initialize()
///
/// # Invoke hooks
/// result, contexts = await manager.invoke_hook(
///     "prompt_pre_fetch",
///     {"prompt_id": "123", "name": "test"},
///     {"request_id": "456"}
/// )
/// ```
#[pymodule]
fn cpex_native(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyPluginManager>()?;
    m.add_class::<PyPluginMode>()?;
    m.add_class::<PyOnError>()?;
    m.add_class::<PyPluginConfig>()?;
    m.add_class::<PyPluginResult>()?;
    m.add_class::<PyPluginContext>()?;
    m.add_class::<PyPluginContextTable>()?;
    m.add_class::<PyExtensions>()?;
    m.add_class::<PyMessagePayload>()?;
    Ok(())
}

// Made with Bob
