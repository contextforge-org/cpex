// Location: ./crates/cpex-wasm-plugin/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// CPEX WASM Plugin SDK.
//
// Provides:
// - `register_wasm_plugin!(PluginType, [HookType, ...])` macro — generates
//   the WIT `Guest` impl with automatic dispatch to `HookHandler<H>` impls.
// - Conversion functions exposed for advanced use cases.
//
// Plugin authors implement `HookHandler<H>` on their type (identical to native
// plugins) and call the macro once — the WIT glue is fully generated.

pub mod conversions;
mod plugins;

// Generate Rust bindings from the WIT world definition.
wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});

pub use conversions::{
    native_payload_to_wit, native_result_to_hook_result, native_result_to_hook_result_generic,
    wit_context_to_native, wit_extensions_to_native, wit_payload_to_native,
};

// ---------------------------------------------------------------------------
// Structured host logging — calls the host-logging import
// ---------------------------------------------------------------------------

/// Log level for host-side structured logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Send a structured log message to the host's tracing infrastructure.
///
/// The host routes this to its `tracing` subscriber with the plugin name
/// attached as a span field. Use this instead of `eprintln!` for production
/// logging.
pub fn host_log(level: LogLevel, message: &str) {
    // In test mode, the WIT host import doesn't exist — fall back to eprintln
    #[cfg(test)]
    {
        eprintln!("[{:?}] {}", level, message);
        return;
    }

    #[cfg(not(test))]
    {
        use crate::cpex::plugin::host_logging;

        let wit_level = match level {
            LogLevel::Trace => host_logging::LogLevel::Trace,
            LogLevel::Debug => host_logging::LogLevel::Debug,
            LogLevel::Info => host_logging::LogLevel::Info,
            LogLevel::Warn => host_logging::LogLevel::Warn,
            LogLevel::Error => host_logging::LogLevel::Error,
        };

        host_logging::log(wit_level, message);
    }
}

/// Convenience macro for structured host logging with format arguments.
///
/// # Example
/// ```no_run
/// cpex_log!(info, "processed {} items in {}ms", count, elapsed);
/// cpex_log!(warn, "payload field missing, using default");
/// ```
#[macro_export]
macro_rules! cpex_log {
    (trace, $($arg:tt)*) => {
        $crate::host_log($crate::LogLevel::Trace, &format!($($arg)*))
    };
    (debug, $($arg:tt)*) => {
        $crate::host_log($crate::LogLevel::Debug, &format!($($arg)*))
    };
    (info, $($arg:tt)*) => {
        $crate::host_log($crate::LogLevel::Info, &format!($($arg)*))
    };
    (warn, $($arg:tt)*) => {
        $crate::host_log($crate::LogLevel::Warn, &format!($($arg)*))
    };
    (error, $($arg:tt)*) => {
        $crate::host_log($crate::LogLevel::Error, &format!($($arg)*))
    };
}

// ---------------------------------------------------------------------------
// register_wasm_plugin! — the core macro
//
// Generates a complete `Guest` impl that:
// 1. Receives WIT types from the host (hook-name, payload, extensions, ctx)
// 2. Converts WIT → cpex-core native types
// 3. Routes to the matching HookHandler<H> based on the payload's concrete type
// 4. Converts PluginResult → WIT HookResult (with context writeback)
//
// Dispatch is built at compile time from the hook type list: every listed
// hook's `Payload` must implement `WasmSerializablePayload`. A CMF payload
// routes to the hook whose Payload is `MessagePayload`; a custom payload
// routes to the hook whose Payload matches the WIT type discriminator
// (e.g. "cpex.identity" → HookHandler<IdentityHook>).
//
// Payloads no listed hook handles return allow() — same as a native plugin
// that isn't registered for that hook. A payload that names a listed type
// but fails to decode returns a deny violation: silently allowing on a
// decode failure would skip whatever check this plugin enforces.
//
// Usage:
//   register_wasm_plugin!(MyPlugin, [CmfHook, IdentityHook]);
// ---------------------------------------------------------------------------

#[macro_export]
macro_rules! register_wasm_plugin {
    ($plugin_ty:ty, [$($hook_ty:ty),+ $(,)?]) => {
        struct _WasmGuestImpl;

        impl Guest for _WasmGuestImpl {
            fn handle_hook(
                hook_name: String,
                payload: HookPayload,
                extensions: Extensions,
                ctx: PluginContext,
            ) -> HookResult {
                use cpex_core::hooks::payload::WasmSerializablePayload;
                use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef};

                let native_ext = $crate::wit_extensions_to_native(extensions);
                let mut native_ctx = $crate::wit_context_to_native(ctx);

                match payload {
                    HookPayload::Cmf(mp) => {
                        let native_payload = $crate::wit_payload_to_native(mp);
                        let any: &dyn ::std::any::Any = &native_payload;
                        $(
                            if let Some(typed) =
                                any.downcast_ref::<<$hook_ty as HookTypeDef>::Payload>()
                            {
                                let plugin = <$plugin_ty>::default();

                                // WASM is single-threaded with no ambient async
                                // runtime. Drive the future synchronously.
                                let result = $crate::__block_on(
                                    <$plugin_ty as HookHandler<$hook_ty>>::handle(
                                        &plugin,
                                        typed,
                                        &native_ext,
                                        &mut native_ctx,
                                    )
                                );
                                return $crate::native_result_to_hook_result_generic(
                                    result, &native_ctx,
                                );
                            }
                        )+
                        eprintln!(
                            "[WASM] no handler for CMF payload on hook '{}' — allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    HookPayload::Identity(_ip) => {
                        eprintln!(
                            "[WASM] received Identity variant on hook '{}' — allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    HookPayload::Delegation(_dp) => {
                        eprintln!(
                            "[WASM] received Delegation variant on hook '{}' — allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    HookPayload::Custom(gp) => {
                        $(
                            if gp.payload_type
                                == <<$hook_ty as HookTypeDef>::Payload
                                    as WasmSerializablePayload>::payload_type_name()
                            {
                                match <<$hook_ty as HookTypeDef>::Payload
                                    as WasmSerializablePayload>::from_wasm_bytes(&gp.payload_data)
                                {
                                    Ok(typed) => {
                                        let plugin = <$plugin_ty>::default();
                                        let result = $crate::__block_on(
                                            <$plugin_ty as HookHandler<$hook_ty>>::handle(
                                                &plugin,
                                                &typed,
                                                &native_ext,
                                                &mut native_ctx,
                                            )
                                        );
                                        return $crate::native_result_to_hook_result_generic(
                                            result, &native_ctx,
                                        );
                                    }
                                    Err(e) => {
                                        return $crate::__decode_error_hook_result(
                                            &gp.payload_type, &e.to_string(), &native_ctx,
                                        );
                                    }
                                }
                            }
                        )+
                        eprintln!(
                            "[WASM] unhandled custom payload '{}' on hook '{}' — allow",
                            gp.payload_type, hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                }
            }
        }

        export!(_WasmGuestImpl);
    };
}

// ---------------------------------------------------------------------------
// Macro support functions — HookResult constructors used by the generated
// dispatch. Public so the expanded macro can call them, not part of the
// plugin-author API.
// ---------------------------------------------------------------------------

/// Allow-and-continue result for payloads this plugin has no handler for.
pub fn __allow_hook_result(ctx: &cpex_core::context::PluginContext) -> HookResult {
    HookResult {
        continue_processing: true,
        modified_payload: None,
        modified_extensions: None,
        modified_context: Some(conversions::native_context_to_wit(ctx)),
        violation: None,
        metadata: None,
    }
}

/// Deny result for a payload the plugin declares a handler for but could
/// not decode — failing open here would silently skip the plugin's check.
pub fn __decode_error_hook_result(
    payload_type: &str,
    error: &str,
    ctx: &cpex_core::context::PluginContext,
) -> HookResult {
    eprintln!("[WASM] failed to decode payload '{}': {}", payload_type, error);
    HookResult {
        continue_processing: false,
        modified_payload: None,
        modified_extensions: None,
        modified_context: Some(conversions::native_context_to_wit(ctx)),
        violation: Some(crate::cpex::plugin::types::PluginViolation {
            code: "wasm_payload_decode_error".to_string(),
            reason: format!("failed to decode payload '{}': {}", payload_type, error),
            description: None,
            details: "{}".to_string(),
            plugin_name: None,
            proto_error_code: None,
        }),
        metadata: None,
    }
}

// ---------------------------------------------------------------------------
// __block_on — synchronous async executor for WASM
//
// Futures returned by HookHandler::handle() must be driven to completion
// synchronously. Current handlers await nothing in WASM context, so the
// future completes on the first poll in practice.
// ---------------------------------------------------------------------------

pub fn __block_on<F: std::future::Future>(f: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop(_: *const ()) {}
    fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut pinned = std::pin::pin!(f);

    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin registration — feature-gated
//
// Each feature compiles a different plugin into the .wasm binary.
// Build with: cargo build --target wasm32-wasip2 --features <plugin> --no-default-features
// ---------------------------------------------------------------------------

#[cfg(all(feature = "identity-checker", not(test)))]
register_wasm_plugin!(
    plugins::identity_checker::IdentityCheckerPlugin,
    [cpex_core::cmf::CmfHook, cpex_core::identity::IdentityHook]
);

#[cfg(all(feature = "header-injector", not(test)))]
register_wasm_plugin!(
    plugins::header_injector::HeaderInjectorPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "audit-logger", not(test)))]
register_wasm_plugin!(
    plugins::audit_logger::AuditLoggerPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "token-attenuator", not(test)))]
register_wasm_plugin!(
    plugins::token_attenuator::TokenAttenuatorPlugin,
    [cpex_core::delegation::TokenDelegateHook]
);

#[cfg(all(feature = "noop", not(test)))]
register_wasm_plugin!(
    plugins::noop::NoopPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "fs-test", not(test)))]
register_wasm_plugin!(
    plugins::fs_test::FsTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "net-test", not(test)))]
register_wasm_plugin!(
    plugins::net_test::NetTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "env-test", not(test)))]
register_wasm_plugin!(
    plugins::env_test::EnvTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "tool-invoke-checker", not(test)))]
register_wasm_plugin!(
    plugins::tool_invoke_checker::ToolInvokeCheckerPlugin,
    [
        plugins::tool_invoke_checker::ToolPreInvoke,
        plugins::tool_invoke_checker::ToolPostInvoke,
    ]
);

#[cfg(all(feature = "pii-guard", not(test)))]
register_wasm_plugin!(
    plugins::pii_guard::PiiGuardPlugin,
    [plugins::pii_guard::ToolPreInvoke]
);

#[cfg(all(feature = "audit-logger-custom", not(test)))]
register_wasm_plugin!(
    plugins::audit_logger_custom::AuditLoggerCustomPlugin,
    [
        plugins::audit_logger_custom::ToolPreInvoke,
        plugins::audit_logger_custom::ToolPostInvoke,
    ]
);

#[cfg(all(feature = "remote-authz", not(test)))]
register_wasm_plugin!(
    plugins::remote_authz::RemoteAuthzPlugin,
    [plugins::remote_authz::ToolPreInvoke]
);

#[cfg(all(feature = "compute-bench", not(test)))]
register_wasm_plugin!(
    plugins::compute_bench::ComputeBenchPlugin,
    [cpex_core::cmf::CmfHook]
);

// ---------------------------------------------------------------------------
// Unit tests — run natively with `cargo test`
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod tests {
    use std::sync::Arc;
    use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall, ToolResult};
    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::container::Extensions;
    use cpex_core::extensions::http::HttpExtension;
    use cpex_core::extensions::security::{SecurityExtension, SubjectExtension, SubjectType};
    use cpex_core::hooks::payload::PluginPayload;
    use cpex_core::hooks::trait_def::PluginResult;

    trait ResultAssert<P: PluginPayload> {
        fn assert_allowed(&self);
        fn assert_denied(&self);
        fn assert_has_modified_payload(&self);
        fn assert_has_modified_extensions(&self);
    }

    impl<P: PluginPayload> ResultAssert<P> for PluginResult<P> {
        fn assert_allowed(&self) {
            assert!(self.continue_processing, "expected ALLOW, got DENY");
        }
        fn assert_denied(&self) {
            assert!(!self.continue_processing, "expected DENY, got ALLOW");
            assert!(self.violation.is_some(), "denied but no violation");
        }
        fn assert_has_modified_payload(&self) {
            assert!(self.modified_payload.is_some(), "expected modified payload");
        }
        fn assert_has_modified_extensions(&self) {
            assert!(self.modified_extensions.is_some(), "expected modified extensions");
        }
    }

    fn tool_call_payload(name: &str) -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: format!("tc_{}", name),
                        name: name.into(),
                        arguments: Default::default(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    fn tool_result_payload(name: &str, content: serde_json::Value, is_error: bool) -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    content: ToolResult {
                        tool_call_id: format!("tc_{}", name),
                        tool_name: name.into(),
                        content,
                        is_error,
                    },
                }],
                channel: None,
            },
        }
    }

    fn ext_with_security(f: impl FnOnce(&mut SecurityExtension)) -> Extensions {
        let mut sec = SecurityExtension::default();
        f(&mut sec);
        Extensions { security: Some(Arc::new(sec)), ..Default::default() }
    }

    #[cfg(feature = "identity-checker")]
    mod identity_checker {
        use super::*;
        use crate::plugins::identity_checker::IdentityCheckerPlugin;
        use cpex_core::cmf::CmfHook;
        use cpex_core::hooks::trait_def::HookHandler;

        #[tokio::test]
        async fn test_denies_pii_access_without_hr_admin_role() {
            let ext = ext_with_security(|s| {
                s.add_label("PII");
                s.subject = Some(SubjectExtension {
                    id: Some("bob".into()),
                    subject_type: Some(SubjectType::User),
                    roles: ["viewer".to_string()].into(),
                    ..Default::default()
                });
            });
            let payload = tool_call_payload("get_compensation");
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <IdentityCheckerPlugin as HookHandler<CmfHook>>::handle(
                    &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_denied();
        }

        #[tokio::test]
        async fn test_allows_pii_access_with_hr_admin_role() {
            let ext = ext_with_security(|s| {
                s.add_label("PII");
                s.subject = Some(SubjectExtension {
                    id: Some("alice".into()),
                    subject_type: Some(SubjectType::User),
                    roles: ["hr_admin".to_string()].into(),
                    ..Default::default()
                });
            });
            let payload = tool_call_payload("get_compensation");
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <IdentityCheckerPlugin as HookHandler<CmfHook>>::handle(
                    &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
        }

        #[tokio::test]
        async fn test_allows_non_pii_without_role() {
            let ext = ext_with_security(|s| s.add_label("PUBLIC"));
            let payload = tool_call_payload("get_weather");
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <IdentityCheckerPlugin as HookHandler<CmfHook>>::handle(
                    &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
        }

        use cpex_core::identity::{IdentityHook, IdentityPayload, TokenSource};
        use std::collections::HashMap;

        #[tokio::test]
        async fn test_identity_resolves_subject_from_header() {
            let mut headers = HashMap::new();
            headers.insert("x-user-id".to_string(), "alice".to_string());
            let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);
            let ext = Extensions::default();
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <IdentityCheckerPlugin as HookHandler<IdentityHook>>::handle(
                    &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
            result.assert_has_modified_payload();
            let subject = result.modified_payload.as_ref().unwrap()
                .subject.as_ref().expect("subject should be resolved");
            assert_eq!(subject.id.as_deref(), Some("alice"));
            assert_eq!(subject.subject_type, Some(SubjectType::User));
        }

        #[tokio::test]
        async fn test_identity_passes_through_without_header() {
            let payload = IdentityPayload::new("", TokenSource::Bearer);
            let ext = Extensions::default();
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <IdentityCheckerPlugin as HookHandler<IdentityHook>>::handle(
                    &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
            assert!(result.modified_payload.is_none());
        }

        #[tokio::test]
        async fn test_identity_skips_when_subject_already_resolved() {
            let mut headers = HashMap::new();
            headers.insert("x-user-id".to_string(), "bob".to_string());
            let mut payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);
            payload.subject = Some(SubjectExtension {
                id: Some("existing-user".into()),
                subject_type: Some(SubjectType::User),
                ..Default::default()
            });
            let ext = Extensions::default();
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <IdentityCheckerPlugin as HookHandler<IdentityHook>>::handle(
                    &IdentityCheckerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
            assert!(result.modified_payload.is_none());
        }
    }

    #[cfg(feature = "header-injector")]
    mod header_injector {
        use super::*;
        use crate::plugins::header_injector::HeaderInjectorPlugin;
        use cpex_core::cmf::CmfHook;
        use cpex_core::hooks::trait_def::HookHandler;

        #[tokio::test]
        async fn test_injects_header_and_label() {
            let mut sec = SecurityExtension::default();
            sec.add_label("PII");
            let mut http = HttpExtension::default();
            http.set_header("Authorization", "Bearer token");
            let ext = Extensions {
                security: Some(Arc::new(sec)),
                http: Some(Arc::new(http)),
                ..Default::default()
            };
            let payload = tool_call_payload("fetch-data");
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <HeaderInjectorPlugin as HookHandler<CmfHook>>::handle(
                    &HeaderInjectorPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
            result.assert_has_modified_extensions();

            let modified = result.modified_extensions.as_ref().unwrap();
            assert!(modified.security.as_ref().unwrap().has_label("PROCESSED"));
            assert!(modified.security.as_ref().unwrap().has_label("PII"));
            let h = modified.http.as_ref().unwrap().read();
            assert_eq!(h.request_headers.get("X-Processed-By").map(|s| s.as_str()), Some("header-injector"));
        }
    }

    #[cfg(feature = "audit-logger")]
    mod audit_logger {
        use super::*;
        use crate::plugins::audit_logger::AuditLoggerPlugin;
        use cpex_core::cmf::CmfHook;
        use cpex_core::hooks::trait_def::HookHandler;

        #[tokio::test]
        async fn test_always_allows_pre_invoke() {
            let mut sec = SecurityExtension::default();
            sec.add_label("PII");
            let mut http = HttpExtension::default();
            http.set_header("X-Request-ID", "req-123");
            let ext = Extensions {
                security: Some(Arc::new(sec)),
                http: Some(Arc::new(http)),
                ..Default::default()
            };
            let payload = tool_call_payload("get_data");
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <AuditLoggerPlugin as HookHandler<CmfHook>>::handle(
                    &AuditLoggerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
        }

        #[tokio::test]
        async fn test_always_allows_post_invoke() {
            let ext = Extensions::default();
            let payload = tool_result_payload("get_data", serde_json::json!({"result": "ok"}), false);
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <AuditLoggerPlugin as HookHandler<CmfHook>>::handle(
                    &AuditLoggerPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
        }
    }

    #[cfg(feature = "token-attenuator")]
    mod token_attenuator {
        use super::*;
        use crate::plugins::token_attenuator::TokenAttenuatorPlugin;
        use cpex_core::delegation::{DelegationPayload, TargetType, TokenDelegateHook};
        use cpex_core::hooks::trait_def::HookHandler;

        #[tokio::test]
        async fn test_mints_token_for_tool_target() {
            let payload = DelegationPayload::new("", "get_compensation")
                .with_target_type(TargetType::Tool)
                .with_target_audience("hr-service.internal")
                .with_required_permissions(vec!["read_compensation".into()]);
            let ext = Extensions::default();
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <TokenAttenuatorPlugin as HookHandler<TokenDelegateHook>>::handle(
                    &TokenAttenuatorPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
            result.assert_has_modified_payload();

            let modified = result.modified_payload.as_ref().unwrap();
            let token = modified.delegated_token.as_ref().expect("should mint token");
            assert_eq!(token.audience, "hr-service.internal");
            assert_eq!(token.scopes, vec!["read_compensation"]);
            assert_eq!(token.outbound_header, "Authorization");
            assert!(modified.minted_at.is_some());
            assert_eq!(modified.metadata.get("minter").and_then(|v| v.as_str()), Some("token-attenuator-wasm"));
        }

        #[tokio::test]
        async fn test_passes_through_non_tool_targets() {
            let payload = DelegationPayload::new("", "agent-downstream")
                .with_target_type(TargetType::Agent);
            let ext = Extensions::default();
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <TokenAttenuatorPlugin as HookHandler<TokenDelegateHook>>::handle(
                    &TokenAttenuatorPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_allowed();
            assert!(result.modified_payload.is_none());
        }

        #[tokio::test]
        async fn test_uses_target_name_as_audience_when_no_explicit_audience() {
            let payload = DelegationPayload::new("", "fetch-records")
                .with_target_type(TargetType::Tool);
            let ext = Extensions::default();
            let mut ctx = PluginContext::default();

            let result: PluginResult<_> =
                <TokenAttenuatorPlugin as HookHandler<TokenDelegateHook>>::handle(
                    &TokenAttenuatorPlugin, &payload, &ext, &mut ctx,
                ).await;
            result.assert_has_modified_payload();
            let token = result.modified_payload.as_ref().unwrap()
                .delegated_token.as_ref().unwrap();
            assert_eq!(token.audience, "fetch-records");
        }
    }
}
