use crate::cmf::message::MessagePayload;
use crate::context::PluginContext;
use crate::extensions::Extensions;
use crate::hooks::PluginResult;

pub fn inject_headers(_payload: &MessagePayload, extensions: &Extensions, _ctx: &PluginContext) -> PluginResult<MessagePayload> {
    if let Some(ref http) = extensions.http {
        println!(
            "  [header-injector] HTTP headers visible: {:?}",
            http.request_headers
        );
    }

    if let Some(ref security) = extensions.security {
        if security.subject.is_some() {
            println!("  [header-injector] WARNING: Subject visible (unexpected!)");
        } else {
            println!("  [header-injector] Security subject: not visible (no read_subject)");
        }
    }

    let mut modified = extensions.cow_copy();

    if modified.labels_write_token.is_some() {
        modified.security.as_mut().unwrap().add_label("PROCESSED");
        println!("  [header-injector] Added label 'PROCESSED'");
    }

    if let Some(ref token) = modified.http_write_token {
        modified
            .http
            .as_mut()
            .unwrap()
            .write(token)
            .set_header("X-Processed-By", "header-injector");
        println!("  [header-injector] Injected header 'X-Processed-By'");
    }

    PluginResult::modify_extensions(modified)
}
