//! Performance benchmarks: WASM plugin invocation vs native handler.
//!
//! Measures the isolation tax of running the same logic through the
//! WASM sandbox vs calling the handler directly.
//!
//! Run: cargo bench -p cpex-wasm-host

use std::path::PathBuf;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use async_trait::async_trait;
use cpex_core::cmf::message::MessagePayload;
use cpex_core::cmf::{CmfHook, ContentPart, Message, Role, ToolCall};
use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::http::HttpExtension;
use cpex_core::extensions::request::RequestExtension;
use cpex_core::extensions::security::SecurityExtension;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use cpex_wasm_host::conversions::{native_context_to_wit, native_extensions_to_wit, native_payload_to_wit};
use cpex_wasm_host::sandbox_manager::{SandboxManager, SharedEngine};

// ---------------------------------------------------------------------------
// Native noop handler (baseline)
// ---------------------------------------------------------------------------

struct NativeNoopPlugin;

static BENCH_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for NativeNoopPlugin {
    fn config(&self) -> &PluginConfig {
        BENCH_CONFIG.get_or_init(|| PluginConfig {
            name: "native-noop-bench".into(),
            kind: "builtin".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            ..Default::default()
        })
    }
    async fn initialize(&self) -> Result<(), Box<PluginError>> { Ok(()) }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> { Ok(()) }
}

impl HookHandler<CmfHook> for NativeNoopPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn make_payload() -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".into(),
                    name: "get_data".into(),
                    arguments: [("id".to_string(), serde_json::json!(42))].into(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

fn make_minimal_extensions() -> Extensions {
    Extensions::default()
}

fn make_full_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label("PII");
    security.add_label("HR_DATA");

    let mut http = HttpExtension::default();
    http.set_header("Authorization", "Bearer eyJ...");
    http.set_header("X-Request-ID", "req-abc-123");
    http.set_header("Content-Type", "application/json");

    Extensions {
        request: Some(Arc::new(RequestExtension {
            request_id: Some("req-abc-123".into()),
            environment: Some("production".into()),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_native_noop(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let payload = make_payload();
    let ext = make_minimal_extensions();

    c.bench_function("native_noop", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = PluginContext::default();
            let result = NativeNoopPlugin.handle(
                black_box(&payload),
                black_box(&ext),
                &mut ctx,
            ).await;
            black_box(result);
        });
    });
}

fn bench_wasm_noop(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/noop.wasm");

    if !wasm_path.exists() {
        eprintln!("SKIP: noop.wasm not found at {}. Build with:", wasm_path.display());
        eprintln!("  cd crates/cpex-wasm-plugin && cargo build --target wasm32-wasip2 --release --features noop --no-default-features");
        return;
    }

    let sandbox = rt.block_on(async {
        let shared = SharedEngine::new().unwrap();
        let mut mgr = SandboxManager::with_shared_engine(&shared);
        mgr.load_wasmplugin(&wasm_path, None, "noop-bench").await.unwrap();
        Arc::new(Mutex::new(mgr))
    });

    let payload = make_payload();
    let ext = make_minimal_extensions();

    c.bench_function("wasm_noop", |b| {
        b.to_async(&rt).iter(|| {
            let sandbox = sandbox.clone();
            let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
                native_payload_to_wit(&payload),
            );
            let wit_ext = native_extensions_to_wit(&ext);
            let wit_ctx = native_context_to_wit(&PluginContext::default());
            async move {
                let mut mgr = sandbox.lock().await;
                let result = mgr.invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                    .await
                    .unwrap();
                black_box(result);
            }
        });
    });
}

fn bench_wasm_with_extensions(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/noop.wasm");

    if !wasm_path.exists() {
        return;
    }

    let sandbox = rt.block_on(async {
        let shared = SharedEngine::new().unwrap();
        let mut mgr = SandboxManager::with_shared_engine(&shared);
        mgr.load_wasmplugin(&wasm_path, None, "noop-bench-ext").await.unwrap();
        Arc::new(Mutex::new(mgr))
    });

    let payload = make_payload();
    let ext = make_full_extensions();

    c.bench_function("wasm_with_full_extensions", |b| {
        b.to_async(&rt).iter(|| {
            let sandbox = sandbox.clone();
            let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
                native_payload_to_wit(&payload),
            );
            let wit_ext = native_extensions_to_wit(&ext);
            let wit_ctx = native_context_to_wit(&PluginContext::default());
            async move {
                let mut mgr = sandbox.lock().await;
                let result = mgr.invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                    .await
                    .unwrap();
                black_box(result);
            }
        });
    });
}

fn bench_conversion_only(c: &mut Criterion) {
    let payload = make_payload();
    let ext = make_full_extensions();
    let ctx = PluginContext::default();

    c.bench_function("conversion_native_to_wit", |b| {
        b.iter(|| {
            let _wp = native_payload_to_wit(black_box(&payload));
            let _we = native_extensions_to_wit(black_box(&ext));
            let _wc = native_context_to_wit(black_box(&ctx));
        });
    });
}

fn bench_native_with_extensions(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let payload = make_payload();
    let ext = make_full_extensions();

    c.bench_function("native_with_full_extensions", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = PluginContext::default();
            let result = NativeNoopPlugin.handle(
                black_box(&payload),
                black_box(&ext),
                &mut ctx,
            ).await;
            black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_native_noop,
    bench_native_with_extensions,
    bench_conversion_only,
    bench_wasm_noop,
    bench_wasm_with_extensions,
);
criterion_main!(benches);
