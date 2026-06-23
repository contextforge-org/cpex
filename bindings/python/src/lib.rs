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
mod wrappers;

use manager::PyPluginManager;
use result::PyPipelineResult;
use wrappers::{
    PyAgentExtension, PyAudioSource, PyAuthorizationDetail, PyClientExtension,
    PyCompletionExtension, PyContentPart, PyConversationContext, PyDelegationExtension,
    PyDelegationHop, PyDelegationPayload, PyDocumentSource, PyExtensions, PyFrameworkExtension,
    PyHttpExtension, PyIdentityPayload, PyImageSource, PyLLMExtension, PyMCPExtension, PyMessage,
    PyMetaExtension, PyPromptMetadata, PyProvenanceExtension, PyPromptRequest, PyPromptResult,
    PyRequestExtension, PyResource, PyResourceMetadata, PyResourceReference, PySecurityExtension,
    PySubjectExtension, PyTokenUsage, PyToolCall, PyToolMetadata, PyToolResult, PyVideoSource,
    PyWorkloadIdentity,
};

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

    // Typed wrapper handles (alternative to dict conversion).
    // CMF message + content parts.
    m.add_class::<PyMessage>()?;
    m.add_class::<PyContentPart>()?;
    m.add_class::<PyToolCall>()?;
    m.add_class::<PyToolResult>()?;
    m.add_class::<PyResource>()?;
    m.add_class::<PyResourceReference>()?;
    m.add_class::<PyPromptRequest>()?;
    m.add_class::<PyPromptResult>()?;
    m.add_class::<PyImageSource>()?;
    m.add_class::<PyVideoSource>()?;
    m.add_class::<PyAudioSource>()?;
    m.add_class::<PyDocumentSource>()?;
    // Extensions container + slots.
    m.add_class::<PyExtensions>()?;
    m.add_class::<PySecurityExtension>()?;
    m.add_class::<PySubjectExtension>()?;
    m.add_class::<PyClientExtension>()?;
    m.add_class::<PyWorkloadIdentity>()?;
    m.add_class::<PyRequestExtension>()?;
    m.add_class::<PyAgentExtension>()?;
    m.add_class::<PyHttpExtension>()?;
    m.add_class::<PyMCPExtension>()?;
    m.add_class::<PyCompletionExtension>()?;
    m.add_class::<PyProvenanceExtension>()?;
    m.add_class::<PyLLMExtension>()?;
    m.add_class::<PyFrameworkExtension>()?;
    m.add_class::<PyMetaExtension>()?;
    m.add_class::<PyDelegationExtension>()?;
    m.add_class::<PyDelegationHop>()?;
    // Nested sub-objects returned as handles.
    m.add_class::<PyConversationContext>()?;
    m.add_class::<PyToolMetadata>()?;
    m.add_class::<PyResourceMetadata>()?;
    m.add_class::<PyPromptMetadata>()?;
    m.add_class::<PyTokenUsage>()?;
    m.add_class::<PyAuthorizationDetail>()?;
    // Identity + Delegation payloads.
    m.add_class::<PyIdentityPayload>()?;
    m.add_class::<PyDelegationPayload>()?;

    Ok(())
}
