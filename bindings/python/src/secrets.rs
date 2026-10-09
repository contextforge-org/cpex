// Location: ./bindings/python/src/secrets.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Secret refresh report as it crosses into Python.
//
// PPE resolves every declared secret once, at `initialize`, and never
// re-reads on its own: the host decides when. The report shape and the
// failure kind strings come from `cpex::host::secret_error_kind`, which the
// C FFI (`cpex_refresh_secrets`) uses too, so Go and Python hosts read the
// same fields.

use cpex::host::RefreshSummary;
use praxis_policy_core::secrets::RefreshReport;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// What a refresh changed and what failed, detached from the engine so
/// it can cross the async boundary before the GIL is taken.
pub struct Refresh(RefreshSummary);

impl From<RefreshReport> for Refresh {
    fn from(report: RefreshReport) -> Self {
        Self(RefreshSummary::from(report))
    }
}

impl<'py> IntoPyObject<'py> for Refresh {
    type Target = PyDict;
    type Output = Bound<'py, PyDict>;
    type Error = PyErr;

    /// `{"updated": [str], "unchanged": int, "failed": [{"secret",
    /// "provider", "kind", "message"}]}`.
    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        let failed = PyList::empty(py);
        for f in self.0.failed {
            let entry = PyDict::new(py);
            entry.set_item("secret", f.secret)?;
            entry.set_item("provider", f.provider)?;
            entry.set_item("kind", f.kind)?;
            entry.set_item("message", f.message)?;
            failed.append(entry)?;
        }
        let out = PyDict::new(py);
        out.set_item("updated", self.0.updated)?;
        out.set_item("unchanged", self.0.unchanged)?;
        out.set_item("failed", failed)?;
        Ok(out)
    }
}
