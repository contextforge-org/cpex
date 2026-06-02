mod conversions;

wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});

use conversions::{native_result_to_wit, wit_context_to_native, wit_extensions_to_native, wit_payload_to_native};

// ---------------------------------------------------------------------------
// identity-checker
// ---------------------------------------------------------------------------

#[cfg(feature = "identity-checker")]
struct IdentityCheckerPlugin;

#[cfg(feature = "identity-checker")]
impl Guest for IdentityCheckerPlugin {
    fn handle_hook(
        payload: MessagePayload,
        extensions: Extensions,
        ctx: PluginContext,
    ) -> PluginResult {
        let native_payload = wit_payload_to_native(payload);
        let native_extensions = wit_extensions_to_native(extensions);
        let native_ctx = wit_context_to_native(ctx);

        let result = cpex_payload::plugins::identity_checker::identity_check(
            &native_payload,
            &native_extensions,
            &native_ctx,
        );

        native_result_to_wit(result)
    }
}

#[cfg(feature = "identity-checker")]
export!(IdentityCheckerPlugin);

// ---------------------------------------------------------------------------
// audit-logger
// ---------------------------------------------------------------------------

#[cfg(feature = "audit-logger")]
struct AuditLoggerPlugin;

#[cfg(feature = "audit-logger")]
impl Guest for AuditLoggerPlugin {
    fn handle_hook(
        payload: MessagePayload,
        extensions: Extensions,
        ctx: PluginContext,
    ) -> PluginResult {
        let native_payload = wit_payload_to_native(payload);
        let native_extensions = wit_extensions_to_native(extensions);
        let native_ctx = wit_context_to_native(ctx);

        let result = cpex_payload::plugins::audit_logger::audit_log(
            &native_payload,
            &native_extensions,
            &native_ctx,
        );

        native_result_to_wit(result)
    }
}

#[cfg(feature = "audit-logger")]
export!(AuditLoggerPlugin);

// ---------------------------------------------------------------------------
// header-injector
// ---------------------------------------------------------------------------

#[cfg(feature = "header-injector")]
struct HeaderInjectorPlugin;

#[cfg(feature = "header-injector")]
impl Guest for HeaderInjectorPlugin {
    fn handle_hook(
        payload: MessagePayload,
        extensions: Extensions,
        ctx: PluginContext,
    ) -> PluginResult {
        let native_payload = wit_payload_to_native(payload);
        let native_extensions = wit_extensions_to_native(extensions);
        let native_ctx = wit_context_to_native(ctx);

        let result = cpex_payload::plugins::header_injector::inject_headers(
            &native_payload,
            &native_extensions,
            &native_ctx,
        );

        native_result_to_wit(result)
    }
}

#[cfg(feature = "header-injector")]
export!(HeaderInjectorPlugin);
