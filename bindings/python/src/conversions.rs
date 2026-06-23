// Location: ./bindings/python/src/conversions.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// PyObject ↔ serde_json::Value traversal, payload resolution, and
// modified-payload serialization (R6, R3, KD1, KD2, KD5).
//
// Never calls Python's `json` module from Rust — all conversion is direct
// PyObject inspection / construction (#2 / R6).

use cpex_core::cmf::MessagePayload;
use cpex_core::context::PluginContextTable;
use cpex_core::extensions::Extensions;
use cpex_core::hooks::payload::PluginPayload;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// GenericPayload — local struct for non-CMF hooks (KD5)
// ---------------------------------------------------------------------------

/// Wraps any serde_json::Value for hooks that are not `cmf.*` (KD1, KD2).
///
/// Defined locally because `cpex-core` exports the macro but not the struct
/// itself (the FFI crate defines its own copy too).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericPayload {
    pub value: Value,
}

cpex_core::impl_plugin_payload!(GenericPayload);

// ---------------------------------------------------------------------------
// PyObject → serde_json::Value
// ---------------------------------------------------------------------------

/// Convert a Python object to a `serde_json::Value`.
///
/// Supported types: `bool`, `int`, `float`, `str`, `None`, `list`, `dict`
/// (with `str` keys). Any other type raises `ValueError` naming the type.
///
/// Recursion is capped at 128 levels (R3). `depth` starts at 0.
pub fn pyobj_to_json_value(py: Python<'_>, obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
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
            out.push(pyobj_to_json_value(py, &item, depth + 1)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(d) = obj.cast::<PyDict>() {
        let mut map = Map::with_capacity(d.len());
        for (k, v) in d.iter() {
            let key: String = k.extract().map_err(|_| {
                PyValueError::new_err(
                    "cpex: dict keys must be strings; got a non-string key",
                )
            })?;
            map.insert(key, pyobj_to_json_value(py, &v, depth + 1)?);
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

// ---------------------------------------------------------------------------
// serde_json::Value → PyObject
// ---------------------------------------------------------------------------

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
        }
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any()),
        Value::Array(arr) => {
            let lst = PyList::empty(py);
            for item in arr {
                lst.append(json_value_to_pyobj(py, item)?)?;
            }
            Ok(lst.into_any())
        }
        Value::Object(map) => {
            let d = PyDict::new(py);
            for (k, val) in map {
                d.set_item(k, json_value_to_pyobj(py, val)?)?;
            }
            Ok(d.into_any())
        }
    }
}

// ---------------------------------------------------------------------------
// Payload resolution
// ---------------------------------------------------------------------------

/// Build the correct `Box<dyn PluginPayload>` for a hook.
///
/// `cmf.*` hooks → `MessagePayload` (serde-constructed from the value).
/// All other hook names → `GenericPayload { value }` (KD1, KD2).
///
/// A `from_value` failure on a CMF payload raises `ValueError` rather than
/// silently falling through to GenericPayload — the caller sent a cmf hook
/// with a dict that doesn't match the MessagePayload schema.
pub fn resolve_payload(hook_name: &str, value: Value) -> PyResult<Box<dyn PluginPayload>> {
    if hook_name.starts_with("cmf.") {
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

// ---------------------------------------------------------------------------
// Payload serialization (for modified_payload in PipelineResult)
// ---------------------------------------------------------------------------

/// Serialize a `&dyn PluginPayload` back to a `serde_json::Value`.
///
/// Returns `None` when the payload type is not in the local registry (unknown
/// plugin-returned type). The caller should append a synthetic error record to
/// `PipelineResult.errors` rather than silently dropping the modification (R2).
///
/// Downcast order: `MessagePayload` first (most common for `cmf.*` hooks),
/// then `GenericPayload` — mirrors cpex-ffi's `serialize_payload` ordering.
pub fn serialize_payload(payload: &dyn PluginPayload) -> Option<Value> {
    if let Some(mp) = payload.as_any().downcast_ref::<MessagePayload>() {
        return serde_json::to_value(mp).ok();
    }
    // Identity / Delegation payloads modify in place (e.g. the JWT resolver
    // populates `subject`), so their modified form must serialize back too —
    // mirrors cpex-ffi's PAYLOAD_IDENTITY / PAYLOAD_DELEGATION arms.
    if let Some(idp) = payload
        .as_any()
        .downcast_ref::<cpex_core::identity::IdentityPayload>()
    {
        return serde_json::to_value(idp).ok();
    }
    if let Some(dp) = payload
        .as_any()
        .downcast_ref::<cpex_core::delegation::DelegationPayload>()
    {
        return serde_json::to_value(dp).ok();
    }
    if let Some(gp) = payload.as_any().downcast_ref::<GenericPayload>() {
        return serde_json::to_value(&gp.value).ok();
    }
    None
}

// ---------------------------------------------------------------------------
// Extensions / PluginContextTable helpers
// ---------------------------------------------------------------------------

/// Deserialize Python dict → `Extensions` via serde.
///
/// An empty dict yields `Extensions::default()` (all fields `#[serde(default)]`).
pub fn extensions_from_value(value: Value) -> PyResult<Extensions> {
    serde_json::from_value(value).map_err(|e| {
        PyValueError::new_err(format!("cpex: extensions conversion failed: {e}"))
    })
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
