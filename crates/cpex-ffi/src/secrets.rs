// Location: ./crates/cpex-ffi/src/secrets.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Secret refresh and health over the FFI.
//
// PPE resolves every declared secret once, at `cpex_initialize`, and never
// re-reads on its own: the host decides when. `cpex_refresh_secrets`
// re-reads every value (renewing a Vault token when due) and returns what
// changed and what failed. `cpex_secrets_last_success` reports when a
// provider last re-read all of its values cleanly, so a host can alarm on
// a stale credential.

use std::os::raw::{c_char, c_int};

use cpex::host::{RefreshSummary, secret_error_kind};

use crate::{
    CpexEngineInner, RC_INVALID_HANDLE, RC_INVALID_INPUT, RC_OK, RC_SERIALIZE_ERROR, SafeRun,
    alloc_bytes, c_str_to_slice, run_safely,
};

/// Refresh report as it crosses the FFI, MessagePack-encoded with named
/// fields.
pub type FfiRefreshReport = RefreshSummary;

/// Re-read every declared secret and return what changed and what failed.
///
/// On `RC_OK`, `*report_msgpack_out` / `*report_len_out` hold a
/// MessagePack map `{updated: [str], unchanged: uint, failed: [{secret,
/// provider, kind, message}]}`; free it with `cpex_free_bytes`. A failed
/// re-read is not an error return: it is listed in `failed` and the value
/// keeps its last-good bytes. An engine with no `secrets:` block, or not
/// yet initialized, returns an empty report.
///
/// Returns `RC_OK`, `RC_INVALID_HANDLE` for a null handle,
/// `RC_INVALID_INPUT` for a null out pointer, `RC_SERIALIZE_ERROR`, or
/// `RC_TIMEOUT` / `RC_PANIC` from the FFI safety layer. Out params are
/// null/zero on any non-OK return.
///
/// # Safety
/// `handle` must be a valid engine handle or NULL. Out pointers must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_refresh_secrets(
    handle: *const CpexEngineInner,
    report_msgpack_out: *mut *mut u8,
    report_len_out: *mut c_int,
) -> c_int {
    if report_msgpack_out.is_null() || report_len_out.is_null() {
        return RC_INVALID_INPUT;
    }
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *report_msgpack_out = std::ptr::null_mut();
        *report_len_out = 0;
    }

    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(h) => h,
        None => return RC_INVALID_HANDLE,
    };

    let report = match run_safely(inner.engine.refresh_secrets(), "cpex_refresh_secrets") {
        SafeRun::Ok(r) => r,
        other => return other.rc(),
    };
    // Log only the names and the failure class. The full message stays in
    // the report handed back to the caller.
    for failure in &report.failed {
        tracing::warn!(
            secret = %failure.secret,
            provider = %failure.provider,
            kind = secret_error_kind(&failure.source),
            "cpex_refresh_secrets: secret refresh failed"
        );
    }

    let wire = FfiRefreshReport::from(report);
    let bytes = match rmp_serde::to_vec_named(&wire) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("cpex_refresh_secrets: report serialize failed: {}", e);
            return RC_SERIALIZE_ERROR;
        },
    };
    let (ptr, len) = alloc_bytes(&bytes);
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *report_msgpack_out = ptr;
        *report_len_out = len;
    }
    RC_OK
}

/// When `provider` last re-read all of its values without a failure, in
/// Unix milliseconds (UTC).
///
/// On `RC_OK`, `*unix_ms_out` holds the timestamp, or `0` when there is
/// none: the provider's most recent refresh failed, the name is not a
/// declared provider, or secrets are not resolved yet. Initialization
/// counts as the first success.
///
/// Returns `RC_OK`, `RC_INVALID_HANDLE` for a null handle, or
/// `RC_INVALID_INPUT` for a null out pointer or a missing / non-UTF-8
/// provider name.
///
/// # Safety
/// `handle` must be a valid engine handle or NULL. `provider` must point
/// to `provider_len` bytes. `unix_ms_out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpex_secrets_last_success(
    handle: *const CpexEngineInner,
    provider: *const c_char,
    provider_len: c_int,
    unix_ms_out: *mut i64,
) -> c_int {
    if unix_ms_out.is_null() {
        return RC_INVALID_INPUT;
    }
    // SAFETY: the caller guarantees the output pointers are writable.
    unsafe {
        *unix_ms_out = 0;
    }
    // SAFETY: the caller guarantees `handle` is NULL or a live handle.
    let inner = match unsafe { handle.as_ref() } {
        Some(h) => h,
        None => return RC_INVALID_HANDLE,
    };
    // SAFETY: the caller guarantees `provider` is NULL or points to `provider_len` readable bytes.
    let name = match unsafe { c_str_to_slice(provider, provider_len) } {
        Some(s) => s,
        None => return RC_INVALID_INPUT,
    };
    if let Some(at) = inner.engine.secrets_last_success(name) {
        // SAFETY: the caller guarantees the output pointers are writable.
        unsafe {
            *unix_ms_out = at.timestamp_millis();
        }
    }
    RC_OK
}
