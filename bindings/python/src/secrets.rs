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

use cpex::host::secret_error_kind;
use praxis_policy_core::secrets::RefreshReport;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// One value that failed to re-read.
pub struct RefreshFailure {
    secret: String,
    provider: String,
    kind: &'static str,
    message: String,
}

/// What a refresh changed and what failed, detached from the engine so
/// it can cross the async boundary before the GIL is taken.
pub struct Refresh {
    updated: Vec<String>,
    unchanged: u64,
    failed: Vec<RefreshFailure>,
}

impl From<RefreshReport> for Refresh {
    fn from(report: RefreshReport) -> Self {
        Self {
            updated: report.updated,
            unchanged: report.unchanged as u64,
            failed: report
                .failed
                .into_iter()
                .map(|f| RefreshFailure {
                    kind: secret_error_kind(&f.source),
                    message: f.source.to_string(),
                    secret: f.secret,
                    provider: f.provider,
                })
                .collect(),
        }
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
        for f in self.failed {
            let entry = PyDict::new(py);
            entry.set_item("secret", f.secret)?;
            entry.set_item("provider", f.provider)?;
            entry.set_item("kind", f.kind)?;
            entry.set_item("message", f.message)?;
            failed.append(entry)?;
        }
        let out = PyDict::new(py);
        out.set_item("updated", self.updated)?;
        out.set_item("unchanged", self.unchanged)?;
        out.set_item("failed", failed)?;
        Ok(out)
    }
}
