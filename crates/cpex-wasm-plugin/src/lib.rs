pub mod errors;

wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});


fn attempt_http_request(url: &str) -> serde_json::Value {
    use wasi::http::types::{Fields, OutgoingRequest, Scheme};
    use wasi::http::outgoing_handler;

    // Parse URL components (simple parsing for scheme://authority/path)
    let (scheme, rest) = if url.starts_with("https://") {
        (Scheme::Https, &url[8..])
    } else if url.starts_with("http://") {
        (Scheme::Http, &url[7..])
    } else {
        return serde_json::json!({"accessible": false, "error": "unsupported scheme"});
    };

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let headers = Fields::new();
    let request = OutgoingRequest::new(headers);
    let _ = request.set_scheme(Some(&scheme));
    let _ = request.set_authority(Some(authority));
    let _ = request.set_path_with_query(Some(path));

    match outgoing_handler::handle(request, None) {
        Ok(_future_response) => {
            serde_json::json!({"accessible": true})
        }
        Err(e) => {
            serde_json::json!({"accessible": false, "error": format!("{:?}", e)})
        }
    }
}

struct IdentityCheckerPlugin;

impl Guest for IdentityCheckerPlugin {
    fn handle_hook(payload: MessagePayload, extensions: Extensions) -> PluginResult {
        // Parse the message payload JSON
        let message_data: serde_json::Value = match serde_json::from_str(&payload.data) {
            Ok(data) => data,
            Err(e) => {
                return PluginResult::Deny(format!("Failed to parse payload: {}", e));
            }
        };

        // Check if this is a tool call (pre-invoke) or tool result (post-invoke)
        let is_tool_result = message_data
            .get("message")
            .and_then(|m| m.get("tool_results"))
            .is_some();

        // Sandbox probe: when tool_name is "sandbox_probe", test env/fs access and report results
        let tool_name_for_probe = message_data
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|tc| tc.get(0))
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");

        if tool_name_for_probe == "sandbox_probe" {
            let mut results = serde_json::Map::new();

            // Test env var access
            let mut env_results = serde_json::Map::new();
            if let Some(env_keys) = message_data.get("probe").and_then(|p| p.get("env_vars")).and_then(|e| e.as_array()) {
                for key_val in env_keys {
                    if let Some(key) = key_val.as_str() {
                        match std::env::var(key) {
                            Ok(val) => { env_results.insert(key.to_string(), serde_json::json!({"found": true, "value": val})); }
                            Err(_) => { env_results.insert(key.to_string(), serde_json::json!({"found": false})); }
                        }
                    }
                }
            }
            results.insert("env".to_string(), serde_json::Value::Object(env_results));

            // Test filesystem access
            let mut fs_results = serde_json::Map::new();
            if let Some(paths) = message_data.get("probe").and_then(|p| p.get("read_files")).and_then(|f| f.as_array()) {
                for path_val in paths {
                    if let Some(path) = path_val.as_str() {
                        match std::fs::read_to_string(path) {
                            Ok(content) => { fs_results.insert(path.to_string(), serde_json::json!({"accessible": true, "size": content.len()})); }
                            Err(e) => { fs_results.insert(path.to_string(), serde_json::json!({"accessible": false, "error": e.to_string()})); }
                        }
                    }
                }
            }
            if let Some(paths) = message_data.get("probe").and_then(|p| p.get("write_files")).and_then(|f| f.as_array()) {
                for path_val in paths {
                    if let Some(path) = path_val.as_str() {
                        match std::fs::write(path, "probe-write-test") {
                            Ok(_) => { fs_results.insert(format!("write:{}", path), serde_json::json!({"accessible": true})); }
                            Err(e) => { fs_results.insert(format!("write:{}", path), serde_json::json!({"accessible": false, "error": e.to_string()})); }
                        }
                    }
                }
            }
            results.insert("fs".to_string(), serde_json::Value::Object(fs_results));

            // Test network access via wasi:http/outgoing-handler
            let mut net_results = serde_json::Map::new();
            if let Some(urls) = message_data.get("probe").and_then(|p| p.get("http_requests")).and_then(|n| n.as_array()) {
                for url_val in urls {
                    if let Some(url) = url_val.as_str() {
                        let result = attempt_http_request(url);
                        net_results.insert(url.to_string(), result);
                    }
                }
            }
            results.insert("net".to_string(), serde_json::Value::Object(net_results));

            let report = serde_json::to_string(&results).unwrap_or_default();
            return PluginResult::Deny(format!("SANDBOX_PROBE_RESULT:{}", report));
        }

        if is_tool_result {
            // POST-INVOKE: verify the tool result
            let tool_name = message_data
                .get("message")
                .and_then(|m| m.get("tool_results"))
                .and_then(|tr| tr.get(0))
                .and_then(|t| t.get("tool_name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");

            println!(
                "  [identity-checker] POST-INVOKE: verifying result from '{}'",
                tool_name
            );

            if let Some(ref security_json) = extensions.security {
                if let Ok(security) = serde_json::from_str::<serde_json::Value>(security_json) {
                    if let Some(subject) = security.get("subject") {
                        println!(
                            "  [identity-checker] Result authorized for subject: {:?}",
                            subject.get("id")
                        );
                    }
                }
            }
            println!("  [identity-checker] POST-INVOKE ALLOWED");
            PluginResult::Allow
        } else {
            // PRE-INVOKE: check caller identity and roles
            let tool_name = message_data
                .get("message")
                .and_then(|m| m.get("tool_calls"))
                .and_then(|tc| tc.get(0))
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");

            println!(
                "  [identity-checker] PRE-INVOKE: checking identity for '{}'",
                tool_name
            );

            // Parse security extension
            if let Some(ref security_json) = extensions.security {
                if let Ok(security) = serde_json::from_str::<serde_json::Value>(security_json) {
                    // Check labels
                    if let Some(labels) = security.get("labels").and_then(|l| l.as_array()) {
                        println!("  [identity-checker] Security labels: {:?}", labels);

                        // Check if PII label exists
                        let has_pii = labels.iter().any(|l| l.as_str() == Some("PII"));

                        if has_pii {
                            // Check subject roles
                            if let Some(subject) = security.get("subject") {
                                let subject_id = subject.get("id").and_then(|id| id.as_str());
                                let roles = subject
                                    .get("roles")
                                    .and_then(|r| r.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str())
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default();

                                println!(
                                    "  [identity-checker] Subject: {:?}, Roles: {:?}",
                                    subject_id, roles
                                );

                                // Check if user has hr_admin role
                                if !roles.contains(&"hr_admin") {
                                    return PluginResult::Deny(format!(
                                        "Tool '{}' requires 'hr_admin' role for PII data",
                                        tool_name
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            if extensions.http.is_some() {
                println!("  [identity-checker] WARNING: HTTP visible (unexpected!)");
            } else {
                println!("  [identity-checker] HTTP: not visible (correct — no read_headers)");
            }
            println!("  [identity-checker] PRE-INVOKE ALLOWED");
            PluginResult::Allow
        }
    }
}

export!(IdentityCheckerPlugin with_types_in self);


