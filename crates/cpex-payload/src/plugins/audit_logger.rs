use crate::cmf::message::MessagePayload;
use crate::context::PluginContext;
use crate::extensions::Extensions;
use crate::hooks::PluginResult;

pub fn audit_log(payload: &MessagePayload, extensions: &Extensions, _ctx: &PluginContext) -> PluginResult<MessagePayload> {
    let is_result = payload.message.is_tool_result();
    let phase = if is_result { "POST" } else { "PRE" };

    let tool_name = if is_result {
        payload
            .message
            .get_tool_results()
            .first()
            .map(|tr| tr.tool_name.as_str())
            .unwrap_or("unknown")
    } else {
        payload
            .message
            .get_tool_calls()
            .first()
            .map(|tc| tc.name.as_str())
            .unwrap_or("unknown")
    };

    print!("  [audit-logger] AUDIT[{}]: tool='{}' ", phase, tool_name);

    if let Some(ref security) = extensions.security {
        let labels: Vec<&String> = security.labels.iter().collect();
        print!("labels={:?} ", labels);
    }

    if let Some(ref http) = extensions.http {
        if let Some(req_id) = http.get_header("X-Request-ID") {
            print!("request_id='{}' ", req_id);
        }
    }

    if is_result {
        let is_error = payload
            .message
            .get_tool_results()
            .first()
            .map(|tr| tr.is_error)
            .unwrap_or(false);
        print!("error={} ", is_error);
    }

    println!();
    PluginResult::allow()
}
