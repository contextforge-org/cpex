// Import the generated bindings
mod bindings;

use bindings::Guest;
use bindings::cpex::plugin::types::{MessagePayload, Extensions, PluginResult};

// Simple struct to implement the Guest trait
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

// Export the implementation
bindings::export!(IdentityCheckerPlugin with_types_in bindings);


