// Location: ./bindings/python/src/conversions.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// PyObject ↔ serde_json::Value traversal, payload resolution, and
// modified-payload serialization.
//
// Never calls Python's `json` module from Rust; all conversion is direct
// PyObject inspection / construction (#2).

use praxis_policy_core::cmf::MessagePayload;
use praxis_policy_core::context::PluginContextTable;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::identity::{HOOK_IDENTITY_RESOLVE, IdentityPayload};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::{Map, Value};

/// Wraps any serde_json::Value for hooks that are not `cmf.*`.
///
/// Defined locally because `praxis-policy-core` exports the macro but not the struct
/// itself (the FFI crate defines its own copy too).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericPayload {
    pub value: Value,
}

praxis_policy_core::impl_plugin_payload!(GenericPayload);

/// Convert a Python object to a `serde_json::Value`.
///
/// Supported types: `bool`, `int`, `float`, `str`, `None`, `list`, `dict`
/// (with `str` keys). Any other type raises `ValueError` naming the type.
///
/// Recursion is capped at 128 levels. `depth` starts at 0.
pub fn pyobj_to_json_value(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    depth: usize,
) -> PyResult<Value> {
    if depth > 128 {
        return Err(PyValueError::new_err(
            "cpex: value nesting exceeds maximum depth of 128 levels",
        ));
    }

    // Order matters: check bool before int because `bool` is a subclass of `int` in Python.
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if let Ok(i) = obj.cast::<PyInt>() {
        let n: i64 = i.extract()?;
        return Ok(Value::Number(n.into()));
    }
    if let Ok(f) = obj.cast::<PyFloat>() {
        let v: f64 = f.extract()?;
        let n = serde_json::Number::from_f64(v).ok_or_else(|| {
            PyValueError::new_err(format!("cpex: float value {v} is not a valid JSON number"))
        })?;
        return Ok(Value::Number(n));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        let text: String = s.extract()?;
        return Ok(Value::String(text));
    }
    if let Ok(lst) = obj.cast::<PyList>() {
        let mut out = Vec::with_capacity(lst.len());
        for item in lst.iter() {
            out.push(pyobj_to_json_value(_py, &item, depth + 1)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(d) = obj.cast::<PyDict>() {
        let mut map = Map::with_capacity(d.len());
        for (k, v) in d.iter() {
            let key: String = k.extract().map_err(|_| {
                PyValueError::new_err("cpex: dict keys must be strings; got a non-string key")
            })?;
            map.insert(key, pyobj_to_json_value(_py, &v, depth + 1)?);
        }
        return Ok(Value::Object(map));
    }

    let type_name = obj
        .get_type()
        .qualname()
        .and_then(|s| s.extract::<String>())
        .unwrap_or_else(|_| "unknown".to_string());
    Err(PyValueError::new_err(format!(
        "cpex: cannot convert Python object of type '{type_name}' to a JSON value"
    )))
}

/// Convert a `serde_json::Value` to a Python object.
///
/// `null` → `None`, booleans → `bool`, numbers → `int` or `float`,
/// strings → `str`, arrays → `list`, objects → `dict`.
pub fn json_value_to_pyobj<'py>(py: Python<'py>, v: &Value) -> PyResult<Bound<'py, PyAny>> {
    match v {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any())
            } else {
                Err(PyValueError::new_err(format!(
                    "cpex: JSON number {n} is out of range for Python"
                )))
            }
        },
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any()),
        Value::Array(arr) => {
            let lst = PyList::empty(py);
            for item in arr {
                lst.append(json_value_to_pyobj(py, item)?)?;
            }
            Ok(lst.into_any())
        },
        Value::Object(map) => {
            let d = PyDict::new(py);
            for (k, val) in map {
                d.set_item(k, json_value_to_pyobj(py, val)?)?;
            }
            Ok(d.into_any())
        },
    }
}

/// Raise `ValueError` for a hook name removed in 0.3, naming its
/// replacement. Such a name reaches no handler, so dispatching it would
/// return an allow with no policy evaluated.
pub fn reject_removed_hook(hook_name: &str) -> PyResult<()> {
    match cpex::host::removed_hook_replacement(hook_name) {
        Some(replacement) => Err(PyValueError::new_err(format!(
            "cpex: hook '{hook_name}' was removed; use '{replacement}'"
        ))),
        None => Ok(()),
    }
}

/// Build the correct `Box<dyn PluginPayload>` for a hook.
///
/// `cmf.*` hooks → `MessagePayload` (serde-constructed from the value).
/// `identity.resolve` → `IdentityPayload`. Tokens travel in `headers`;
/// the payload's raw token field is never deserialized. Only the input
/// fields (`source`, `source_header`, `headers`, `client_host`,
/// `client_port`) may be set: a dict that pre-fills a resolver output
/// field (`subject`, `client`, `caller_workload`, `delegation`,
/// `raw_credentials`, `resolved_at`, `raw_claims`) raises `ValueError`,
/// so a caller cannot forge the resolved identity.
/// All other hook names → `GenericPayload { value }`.
///
/// A `from_value` failure on a typed payload raises `ValueError` rather
/// than silently falling through to GenericPayload; the caller sent a dict
/// that doesn't match the hook's payload schema.
pub fn resolve_payload(hook_name: &str, value: Value) -> PyResult<Box<dyn PluginPayload>> {
    if hook_name == HOOK_IDENTITY_RESOLVE {
        let idp: IdentityPayload = serde_json::from_value(value).map_err(|e| {
            PyValueError::new_err(format!(
                "cpex: payload for '{hook_name}' is not a valid IdentityPayload: {e}"
            ))
        })?;
        let resolved = cpex::host::resolved_identity_fields(&idp);
        if !resolved.is_empty() {
            return Err(PyValueError::new_err(format!(
                "cpex: payload for '{hook_name}' must not set resolver output fields: {}",
                resolved.join(", ")
            )));
        }
        Ok(Box::new(idp))
    } else if hook_name.starts_with("cmf.") {
        let msg: MessagePayload = serde_json::from_value(value).map_err(|e| {
            PyValueError::new_err(format!(
                "cpex: payload for '{hook_name}' is not a valid MessagePayload: {e}"
            ))
        })?;
        Ok(Box::new(msg))
    } else {
        Ok(Box::new(GenericPayload { value }))
    }
}

/// Serialize a `&dyn PluginPayload` back to a `serde_json::Value`.
///
/// Returns `None` when the payload type is not in the local registry (unknown
/// plugin-returned type). The caller should append a synthetic error record to
/// `PipelineResult.errors` rather than silently dropping the modification.
///
/// Downcast order: `MessagePayload` first (most common for `cmf.*` hooks),
/// then `IdentityPayload`, then `GenericPayload`; mirrors cpex-ffi's
/// `serialize_payload` ordering.
///
/// An `IdentityPayload` comes back without its `headers`: they are the
/// request headers the caller passed in, including the credential header
/// (`Authorization` and the like), so echoing them would hand the inbound
/// token back to anything that logs or forwards the result. The raw token
/// field is skip-serialized by PPE.
pub fn serialize_payload(payload: &dyn PluginPayload) -> Option<Value> {
    if let Some(mp) = payload.as_any().downcast_ref::<MessagePayload>() {
        return serde_json::to_value(mp).ok();
    }
    if let Some(idp) = payload.as_any().downcast_ref::<IdentityPayload>() {
        let mut value = serde_json::to_value(idp).ok()?;
        if let Value::Object(map) = &mut value {
            map.remove("headers");
        }
        return Some(value);
    }
    if let Some(gp) = payload.as_any().downcast_ref::<GenericPayload>() {
        return serde_json::to_value(&gp.value).ok();
    }
    None
}

/// Deserialize Python dict → `Extensions` via serde.
///
/// An empty dict yields `Extensions::default()` (all fields `#[serde(default)]`).
pub fn extensions_from_value(value: Value) -> PyResult<Extensions> {
    serde_json::from_value(value)
        .map_err(|e| PyValueError::new_err(format!("cpex: extensions conversion failed: {e}")))
}

/// Deserialize Python dict → `Option<PluginContextTable>` via serde.
pub fn context_table_from_value(value: Value) -> PyResult<Option<PluginContextTable>> {
    if value.is_null() {
        return Ok(None);
    }
    let table: PluginContextTable = serde_json::from_value(value).map_err(|e| {
        PyValueError::new_err(format!("cpex: context_table conversion failed: {e}"))
    })?;
    Ok(Some(table))
}
