use crate::cmf::message::MessagePayload;
use crate::context::PluginContext;
use crate::error::PluginViolation;
use crate::extensions::Extensions;
use crate::hooks::PluginResult;

pub fn identity_check(payload: &MessagePayload, extensions: &Extensions, _ctx: &PluginContext) -> PluginResult<MessagePayload> {
    let is_result = payload.message.is_tool_result();

    if is_result {
        let tool_name = payload
            .message
            .get_tool_results()
            .first()
            .map(|tr| tr.tool_name.as_str())
            .unwrap_or("unknown");
        println!(
            "  [identity-checker] POST-INVOKE: verifying result from '{}'",
            tool_name
        );

        if let Some(ref security) = extensions.security {
            if let Some(ref subject) = security.subject {
                println!(
                    "  [identity-checker] Result authorized for subject: {:?}",
                    subject.id
                );
            }
        }
        println!("  [identity-checker] POST-INVOKE ALLOWED");
    } else {
        let tool_name = payload
            .message
            .get_tool_calls()
            .first()
            .map(|tc| tc.name.as_str())
            .unwrap_or("unknown");
        println!(
            "  [identity-checker] PRE-INVOKE: checking identity for '{}'",
            tool_name
        );

        if let Some(ref security) = extensions.security {
            let labels: Vec<&String> = security.labels.iter().collect();
            println!("  [identity-checker] Security labels: {:?}", labels);

            if let Some(ref subject) = security.subject {
                println!(
                    "  [identity-checker] Subject: {:?}, Roles: {:?}",
                    subject.id,
                    subject.roles.iter().collect::<Vec<_>>()
                );

                if security.has_label("PII") && !subject.roles.contains("hr_admin") {
                    return PluginResult::deny(PluginViolation::new(
                        "insufficient_role",
                        &format!(
                            "Tool '{}' requires 'hr_admin' role for PII data",
                            tool_name
                        ),
                    ));
                }
            }
        }

        if extensions.http.is_some() {
            println!("  [identity-checker] WARNING: HTTP visible (unexpected!)");
        } else {
            println!("  [identity-checker] HTTP: not visible (correct — no read_headers)");
        }
        println!("  [identity-checker] PRE-INVOKE ALLOWED");
    }

    PluginResult::allow()
}
