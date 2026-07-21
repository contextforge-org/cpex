//! Comprehensive benchmarks: cold start, real computation, custom payload, concurrency.
//!
//! Complements invocation.rs (which measures isolation overhead) with benchmarks
//! that answer: "how does WASM compare for real work?" and "what's the custom
//! payload path cost?".
//!
//! Run: cargo bench -p cpex-wasm-host --bench comprehensive

use std::path::PathBuf;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::message::MessagePayload;
use cpex_core::cmf::{CmfHook, ContentPart, Message, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::http::HttpExtension;
use cpex_core::extensions::security::SecurityExtension;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use cpex_wasm_host::conversions::{
    native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
};
use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;
use cpex_wasm_host::sandbox_manager::{SandboxManager, SharedEngine};

// ---------------------------------------------------------------------------
// Native compute plugin (identical logic to the WASM compute-bench plugin)
// ---------------------------------------------------------------------------

struct NativeComputePlugin;

static COMPUTE_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for NativeComputePlugin {
    fn config(&self) -> &PluginConfig {
        COMPUTE_CONFIG.get_or_init(|| PluginConfig {
            name: "native-compute-bench".into(),
            kind: "builtin".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            ..Default::default()
        })
    }
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }
}

impl HookHandler<CmfHook> for NativeComputePlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let args_json = payload
            .message
            .get_tool_calls()
            .first()
            .map(|tc| serde_json::to_string(&tc.arguments).unwrap_or_default())
            .unwrap_or_default();

        let mut summary = String::with_capacity(256);
        summary.push_str("tool=");
        summary.push_str(
            payload
                .message
                .get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("?"),
        );
        if let Some(ref sec) = extensions.security {
            for label in sec.labels.iter() {
                summary.push_str(",label=");
                summary.push_str(label);
            }
        }
        if let Some(ref http) = extensions.http {
            if let Some(req_id) = http.get_header("X-Request-ID") {
                summary.push_str(",req_id=");
                summary.push_str(req_id);
            }
        }

        let hash: u64 = args_json.bytes().fold(14695981039346656037u64, |acc, b| {
            acc.wrapping_mul(1099511628211).wrapping_add(b as u64)
        });

        ctx.set_local("hash", serde_json::json!(hash));
        ctx.set_local("summary_len", serde_json::json!(summary.len()));

        PluginResult::allow()
    }
}

// ---------------------------------------------------------------------------
// Custom payload types (for payload path comparison)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolInvokePayload {
    tool_name: String,
    user: String,
    arguments: String,
}

cpex_core::impl_plugin_payload!(ToolInvokePayload);
cpex_core::impl_wasm_payload!(ToolInvokePayload, "cpex.tool_invoke");

#[allow(dead_code)]
struct ToolPreInvoke;
impl HookTypeDef for ToolPreInvoke {
    type Payload = ToolInvokePayload;
    type Result = PluginResult<ToolInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
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
                    name: "get_compensation".into(),
                    arguments: [
                        ("employee_id".to_string(), serde_json::json!(42)),
                        ("department".to_string(), serde_json::json!("engineering")),
                        ("include_bonus".to_string(), serde_json::json!(true)),
                    ]
                    .into(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

fn make_full_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label("PII");
    security.add_label("HR_DATA");
    security.add_label("CONFIDENTIAL");

    let mut http = HttpExtension::default();
    http.set_header(
        "Authorization",
        "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    );
    http.set_header("X-Request-ID", "req-bench-001");
    http.set_header("Content-Type", "application/json");
    http.set_header("X-Correlation-ID", "corr-12345");

    Extensions {
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

fn wasm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm")
}

fn compute_wasm_path() -> PathBuf {
    wasm_dir().join("compute-bench.wasm")
}

fn noop_wasm_path() -> PathBuf {
    wasm_dir().join("noop.wasm")
}

fn tool_invoke_checker_path() -> PathBuf {
    wasm_dir().join("tool-invoke-checker.wasm")
}

// ---------------------------------------------------------------------------
// Benchmark: Cold Start (load + first invocation)
// ---------------------------------------------------------------------------

fn bench_cold_start(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = noop_wasm_path();

    if !wasm_path.exists() {
        eprintln!("SKIP bench_cold_start: noop.wasm not found");
        return;
    }

    let shared = Arc::new(SharedEngine::new().unwrap());

    c.bench_function("cold_start_wasm", |b| {
        b.to_async(&rt).iter(|| {
            let shared = shared.clone();
            let path = wasm_path.clone();
            async move {
                let mut mgr = SandboxManager::with_shared_engine(&shared);
                mgr.load_wasmplugin(&path, None, "cold-start-bench")
                    .await
                    .unwrap();

                let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
                    native_payload_to_wit(&make_payload()),
                );
                let wit_ext = native_extensions_to_wit(&Extensions::default());
                let wit_ctx = native_context_to_wit(&PluginContext::default());
                let result = mgr
                    .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                    .await
                    .unwrap();
                black_box(result);
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Real Computation (native vs WASM)
// ---------------------------------------------------------------------------

fn bench_compute_native(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let payload = make_payload();
    let ext = make_full_extensions();

    c.bench_function("compute_native", |b| {
        b.to_async(&rt).iter(|| async {
            let mut ctx = PluginContext::default();
            let result = NativeComputePlugin
                .handle(black_box(&payload), black_box(&ext), &mut ctx)
                .await;
            black_box(result);
        });
    });
}

fn bench_compute_wasm(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = compute_wasm_path();

    if !wasm_path.exists() {
        eprintln!("SKIP bench_compute_wasm: compute-bench.wasm not found");
        return;
    }

    let sandbox = rt.block_on(async {
        let shared = SharedEngine::new().unwrap();
        let mut mgr = SandboxManager::with_shared_engine(&shared);
        mgr.load_wasmplugin(&wasm_path, None, "compute-bench")
            .await
            .unwrap();
        Arc::new(Mutex::new(mgr))
    });

    let payload = make_payload();
    let ext = make_full_extensions();

    c.bench_function("compute_wasm", |b| {
        b.to_async(&rt).iter(|| {
            let sandbox = sandbox.clone();
            let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
                native_payload_to_wit(&payload),
            );
            let wit_ext = native_extensions_to_wit(&ext);
            let wit_ctx = native_context_to_wit(&PluginContext::default());
            async move {
                let mut mgr = sandbox.lock().await;
                let result = mgr
                    .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                    .await
                    .unwrap();
                black_box(result);
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Custom Payload vs Structured Payload
// ---------------------------------------------------------------------------

fn bench_custom_payload_wasm(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = tool_invoke_checker_path();

    if !wasm_path.exists() {
        eprintln!("SKIP bench_custom_payload_wasm: tool-invoke-checker.wasm not found");
        return;
    }

    let registry = Arc::new({
        let mut r = PayloadSerializerRegistry::new();
        r.register::<ToolInvokePayload>();
        r
    });

    let sandbox = rt.block_on(async {
        let shared = SharedEngine::new().unwrap();
        let mut mgr = SandboxManager::with_shared_engine(&shared);
        mgr.load_wasmplugin(&wasm_path, None, "custom-payload-bench")
            .await
            .unwrap();
        Arc::new(Mutex::new(mgr))
    });

    let custom_payload = ToolInvokePayload {
        tool_name: "get_compensation".into(),
        user: "alice".into(),
        arguments: "employee_id=42".into(),
    };

    c.bench_function("custom_payload_wasm", |b| {
        b.to_async(&rt).iter(|| {
            let sandbox = sandbox.clone();
            let (type_name, bytes) = registry.serialize(&custom_payload).unwrap();
            let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Custom(
                cpex_wasm_host::sandbox_manager::types::CustomPayload {
                    payload_type: type_name.to_string(),
                    payload_data: bytes,
                },
            );
            let wit_ext = native_extensions_to_wit(&Extensions::default());
            let wit_ctx = native_context_to_wit(&PluginContext::default());
            async move {
                let mut mgr = sandbox.lock().await;
                let result = mgr
                    .invoke("tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                    .await
                    .unwrap();
                black_box(result);
            }
        });
    });
}

fn bench_structured_payload_wasm(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = noop_wasm_path();

    if !wasm_path.exists() {
        eprintln!("SKIP bench_structured_payload_wasm: noop.wasm not found");
        return;
    }

    let sandbox = rt.block_on(async {
        let shared = SharedEngine::new().unwrap();
        let mut mgr = SandboxManager::with_shared_engine(&shared);
        mgr.load_wasmplugin(&wasm_path, None, "structured-bench")
            .await
            .unwrap();
        Arc::new(Mutex::new(mgr))
    });

    let payload = make_payload();

    c.bench_function("structured_payload_wasm", |b| {
        b.to_async(&rt).iter(|| {
            let sandbox = sandbox.clone();
            let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
                native_payload_to_wit(&payload),
            );
            let wit_ext = native_extensions_to_wit(&Extensions::default());
            let wit_ctx = native_context_to_wit(&PluginContext::default());
            async move {
                let mut mgr = sandbox.lock().await;
                let result = mgr
                    .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                    .await
                    .unwrap();
                black_box(result);
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Mutex Contention (concurrent access)
// ---------------------------------------------------------------------------

fn bench_concurrent_contention(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let wasm_path = noop_wasm_path();

    if !wasm_path.exists() {
        eprintln!("SKIP bench_concurrent_contention: noop.wasm not found");
        return;
    }

    let sandbox = rt.block_on(async {
        let shared = SharedEngine::new().unwrap();
        let mut mgr = SandboxManager::with_shared_engine(&shared);
        mgr.load_wasmplugin(&wasm_path, None, "contention-bench")
            .await
            .unwrap();
        Arc::new(Mutex::new(mgr))
    });

    let payload = make_payload();
    let ext = Extensions::default();

    let mut group = c.benchmark_group("concurrent_contention");

    for num_tasks in [1, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_tasks),
            &num_tasks,
            |b, &n| {
                b.to_async(&rt).iter(|| {
                    let sandbox = sandbox.clone();
                    let payload = payload.clone();
                    let ext = ext.clone();
                    async move {
                        let mut handles = Vec::with_capacity(n);
                        for _ in 0..n {
                            let sandbox = sandbox.clone();
                            let payload = payload.clone();
                            let ext = ext.clone();
                            handles.push(tokio::spawn(async move {
                                let wit_payload =
                                    cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
                                        native_payload_to_wit(&payload),
                                    );
                                let wit_ext = native_extensions_to_wit(&ext);
                                let wit_ctx = native_context_to_wit(&PluginContext::default());
                                let mut mgr = sandbox.lock().await;
                                let result = mgr
                                    .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
                                    .await
                                    .unwrap();
                                black_box(result);
                            }));
                        }
                        for h in handles {
                            h.await.unwrap();
                        }
                    }
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_cold_start,
    bench_compute_native,
    bench_compute_wasm,
    bench_custom_payload_wasm,
    bench_structured_payload_wasm,
    bench_concurrent_contention,
);
criterion_main!(benches);
