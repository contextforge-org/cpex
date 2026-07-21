// Location: ./examples/tutorial/src/backends.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Fake tool backends for the tutorial. These stand in for the real
// services an agent would call, an HR system, a source-repository
// index, an outbound mailer. They hold hard-coded data and do no
// enforcement of their own: every access decision in the tutorial is
// made by CPEX policy *in front of* these functions, never inside them.
// That separation is the whole point, the same backend returns the
// same bytes regardless of caller; policy decides who sees what.

use serde_json::{json, Value};

/// Look up an employee's full HR record by id. The record includes an
/// SSN and salary; policy (not this function) decides whether the
/// caller may see those fields.
pub fn get_compensation(args: &Value) -> Value {
    let employee_id = args
        .get("employee_id")
        .and_then(Value::as_str)
        .unwrap_or("e-0000");
    // A tiny fake directory. Any unknown id falls back to a stub record
    // so the module scenarios always get a well-formed response.
    match employee_id {
        "e-1001" => json!({
            "employee_id": "e-1001",
            "name": "Alice Okafor",
            "title": "Staff Engineer",
            "salary": 198_000,
            "ssn": "521-38-7710",
        }),
        "e-1002" => json!({
            "employee_id": "e-1002",
            "name": "Ben Underwood",
            "title": "HR Business Partner",
            "salary": 141_500,
            "ssn": "492-11-6034",
        }),
        other => json!({
            "employee_id": other,
            "name": "Unknown Employee",
            "title": "n/a",
            "salary": 0,
            "ssn": "000-00-0000",
        }),
    }
}

/// Search source repositories. Returns a list of repos matching the
/// requested visibility. Backend does no authorization, a policy route
/// gates who may search which visibility.
pub fn search_repos(args: &Value) -> Value {
    let visibility = args
        .get("visibility")
        .and_then(Value::as_str)
        .unwrap_or("internal");
    let all = [
        json!({ "name": "payments-core", "visibility": "internal" }),
        json!({ "name": "fraud-models", "visibility": "internal" }),
        json!({ "name": "brand-site", "visibility": "public" }),
    ];
    let hits: Vec<Value> = all
        .iter()
        .filter(|r| r["visibility"] == visibility)
        .cloned()
        .collect();
    json!({ "visibility": visibility, "repositories": hits })
}

/// Send an outbound email. The backend "sends" by echoing what it would
/// have transmitted. Whether this is allowed to run at all, for
/// instance, after the session has touched compensation data, is a
/// policy decision made before this function is ever reached.
pub fn send_email(args: &Value) -> Value {
    let to = args.get("to").and_then(Value::as_str).unwrap_or("");
    let subject = args.get("subject").and_then(Value::as_str).unwrap_or("");
    json!({ "sent": true, "to": to, "subject": subject })
}

/// Dispatch a tool call by name to the matching backend. Modules that
/// build multi-tool scenarios (the capstone) route through here; simpler
/// modules can call a specific function directly.
pub fn dispatch(tool: &str, args: &Value) -> Value {
    match tool {
        "get_compensation" => get_compensation(args),
        "search_repos" => search_repos(args),
        "send_email" => send_email(args),
        other => json!({ "error": format!("no backend for tool '{other}'") }),
    }
}
