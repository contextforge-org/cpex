// Location: ./bindings/python/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// cpex-python — PyO3 native extension module `cpex._lib`.
//
// Module registration and tokio runtime initialization.
// The runtime is initialized once with a multi-thread builder that honours
// the `CPEX_PY_WORKER_THREADS` environment variable (KD8), mirroring the
// `CPEX_FFI_WORKER_THREADS` knob in cpex-ffi.

use pyo3::prelude::*;

mod builtins;
mod conversions;
mod error;
mod manager;
mod result;

use manager::PyPluginManager;
use result::PyPipelineResult;

/// Name of the env var operators set to bound worker threads.
const ENV_WORKER_THREADS: &str = "CPEX_PY_WORKER_THREADS";

/// Parse `CPEX_PY_WORKER_THREADS`. Returns `Some(n)` for valid positive
/// integers, `None` otherwise (falls back to tokio default `num_cpus`).
fn worker_threads_from_env() -> Option<usize> {
    let raw = std::env::var(ENV_WORKER_THREADS).ok()?;
    match raw.parse::<usize>() {
        Ok(n) if n > 0 => {
            tracing::info!(
                "cpex-python: runtime using {} worker threads (from {})",
                n,
                ENV_WORKER_THREADS,
            );
            Some(n)
        }
        _ => {
            tracing::warn!(
                "cpex-python: {}={:?} is not a positive integer; using num_cpus default",
                ENV_WORKER_THREADS,
                raw,
            );
            None
        }
    }
}

#[pymodule]
fn _lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Initialize the pyo3-async-runtimes tokio runtime with a multi-thread
    // builder so async methods are dispatched onto a real thread pool rather
    // than a single-threaded executor. This must run before any `future_into_py`
    // call — doing it here at module import time is the correct hook (KD8).
    //
    // This is a separate runtime from cpex-ffi's SHARED_RUNTIME; the
    // shared-budget philosophy is mirrored, not the runtime instance.
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = worker_threads_from_env() {
        builder.worker_threads(n);
    }
    pyo3_async_runtimes::tokio::init(builder);

    m.add_class::<PyPluginManager>()?;
    m.add_class::<PyPipelineResult>()?;

    Ok(())
}
