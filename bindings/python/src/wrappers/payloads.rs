// Location: ./bindings/python/src/wrappers/payloads.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed wrappers for the Identity and Delegation hook payloads.
//
// Both impl PluginPayload, so a wrapped handle clones straight into the
// executor with no conversion.
//
// Secret-handling note: the raw token fields — `IdentityPayload.raw_token`,
// `DelegationPayload.bearer_token`, and the token fields inside
// `RawCredentialsExtension` — are all `#[serde(skip)]` in the core. They never
// appear in `to_dict()` and CANNOT be set through the kwargs constructor.
// A Python caller supplies the inbound credential to the JWT resolver via the
// `headers` map instead, e.g. IdentityPayload(source="bearer",
// headers={"authorization": "Bearer <jwt>"}). The resolver reads its configured
// header (default `Authorization`, matched case-insensitively).

use cpex_core::delegation::DelegationPayload;
use cpex_core::identity::IdentityPayload;
use pyo3::prelude::*;

use super::extensions::{
    PyClientExtension, PyDelegationExtension, PySubjectExtension, PyWorkloadIdentity,
};

// Getters cover the `pub` (output) fields. The secret/input fields
// (`raw_token`, `source`, `target_name`, `bearer_token`, ...) are private in
// the core; they round-trip through construction and `to_dict()` but have no
// typed getter. `subject` is bespoke below (returns a typed handle).
// `raw_credentials` / `delegated_token` stay as `convert` (dict): they carry
// secret material the core marks `#[serde(skip)]`, so the dict projection is
// the safe surface. The non-secret nested objects are handle getters below.
serde_wrapper!(PyIdentityPayload, "IdentityPayload", IdentityPayload,
    native: [],
    convert: [raw_credentials, resolved_at, raw_claims]);
serde_wrapper!(PyDelegationPayload, "DelegationPayload", DelegationPayload,
    native: [],
    convert: [delegated_token, delegation_mode, minted_at, metadata]);

#[pymethods]
impl PyIdentityPayload {
    /// The resolved subject identity, if present (typed handle).
    #[getter]
    fn subject(&self) -> Option<PySubjectExtension> {
        self.inner
            .subject
            .as_ref()
            .map(|s| PySubjectExtension { inner: s.clone() })
    }

    #[getter]
    fn client(&self) -> Option<PyClientExtension> {
        self.inner
            .client
            .as_ref()
            .map(|c| PyClientExtension { inner: c.clone() })
    }

    #[getter]
    fn caller_workload(&self) -> Option<PyWorkloadIdentity> {
        self.inner
            .caller_workload
            .as_ref()
            .map(|w| PyWorkloadIdentity { inner: w.clone() })
    }

    #[getter]
    fn delegation(&self) -> Option<PyDelegationExtension> {
        self.inner
            .delegation
            .as_ref()
            .map(|d| PyDelegationExtension { inner: d.clone() })
    }
}

#[pymethods]
impl PyDelegationPayload {
    #[getter]
    fn delegation_update(&self) -> Option<PyDelegationExtension> {
        self.inner
            .delegation_update
            .as_ref()
            .map(|d| PyDelegationExtension { inner: d.clone() })
    }
}
