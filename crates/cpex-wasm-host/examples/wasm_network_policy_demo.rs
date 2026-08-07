// Location: ./crates/cpex-wasm-host/examples/wasm_network_policy_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Network Policy Sandbox Demo
//
// Invokes net-http-test.wasm with a URL and HTTP method as ToolCall arguments.
// Each scenario loads the plugin with a different NetworkRule configuration to
// demonstrate every enforcement dimension:
//
//   1. No policy          — all outbound HTTP denied (deny-by-default)
//   2. Host allowlist     — allowed host passes, unlisted host is denied
//   3. Wildcard host      — *.example.com matches subdomains, not the apex
//   4. Port enforcement   — only port 443 allowed; port 8080 denied
//   5. Scheme enforcement — https-only (default); plain http denied
//   6. Method enforcement — GET only; POST denied
//   7. Multi-rule         — two different hosts with different constraints
//
// Prerequisites:
//   cd crates/cpex-wasm-host && make build-test-plugins
//
// Run:
//   cargo run -p cpex-wasm-host --example wasm_network_policy_demo

use std::collections::HashMap;
use std::path::PathBuf;

use cpex_core::cmf::constants::SCHEMA_VERSION;
use cpex_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use cpex_core::context::PluginContext;
use cpex_core::extensions::container::Extensions;

use cpex_wasm_host::conversions::{
    native_context_to_wit, native_extensions_to_wit, native_payload_to_wit,
};
use cpex_wasm_host::policy_loader::{NetworkRule, SandboxPolicy};
use cpex_wasm_host::sandbox_manager::{SandboxManager, SharedEngine};

// ---------------------------------------------------------------------------
// Terminal colours
// ---------------------------------------------------------------------------

const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[1;36m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/net-http-test.wasm")
}

fn make_payload(url: &str, method: &str) -> MessagePayload {
    let mut arguments = HashMap::new();
    arguments.insert("url".to_string(), serde_json::json!(url));
    arguments.insert("method".to_string(), serde_json::json!(method));
    MessagePayload {
        message: Message {
            schema_version: SCHEMA_VERSION.into(),
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_net".into(),
                    name: "http_check".into(),
                    arguments,
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

async fn invoke(mgr: &mut SandboxManager, url: &str, method: &str) -> String {
    let payload = make_payload(url, method);
    let wit_payload = cpex_wasm_host::sandbox_manager::types::HookPayload::Cmf(
        native_payload_to_wit(&payload),
    );
    let wit_ext = native_extensions_to_wit(&Extensions::default());
    let wit_ctx = native_context_to_wit(&PluginContext::default());

    let result = mgr
        .invoke("cmf.tool_pre_invoke", wit_payload, wit_ext, wit_ctx)
        .await
        .unwrap();

    result
        .modified_context
        .and_then(|ctx| ctx.local_state.into_iter().find(|e| e.key == "http_result"))
        .map(|e| e.value.trim_matches('"').to_string())
        .unwrap_or_else(|| "no_result".to_string())
}

fn print_case(label: &str, method: &str, url: &str, result: &str) {
    let (arrow, color) = if result == "allowed" {
        ("ALLOW", GREEN)
    } else {
        ("DENY ", RED)
    };
    println!(
        "  {}[{}]{} {:6} {}\n  {}→ {}{}",
        DIM, label, RESET, method, url, color, arrow, RESET,
    );
}

async fn load_plugin(shared: &SharedEngine, policy: Option<SandboxPolicy>, name: &str) -> SandboxManager {
    let path = wasm_path();
    let mut mgr = SandboxManager::with_shared_engine(shared);
    mgr.load_wasmplugin(&path, policy.as_ref(), name)
        .await
        .unwrap_or_else(|e| panic!("failed to load plugin '{}': {}", name, e));
    mgr
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("warn".parse().unwrap()),
        )
        .init();

    let path = wasm_path();
    if !path.exists() {
        eprintln!(
            "{}ERROR:{} net-http-test.wasm not found at {}\n\
             Run: cd crates/cpex-wasm-host && make build-test-plugins",
            RED, RESET,
            path.display()
        );
        std::process::exit(1);
    }

    println!("{}=== Network Policy Sandbox Demo ==={}\n", BOLD, RESET);
    println!(
        "{}Plugin:{}  net-http-test.wasm\n\
         {}Payload:{} url + method passed as ToolCall arguments\n\
         {}Result:{}  plugin writes 'allowed' or 'denied' into local_state\n",
        DIM, RESET, DIM, RESET, DIM, RESET
    );

    // Shared wasmtime engine — one epoch thread, each scenario gets its own store
    let shared = SharedEngine::new().unwrap();

    // =========================================================================
    // Scenario 1: No policy — deny-by-default
    // Every outbound request is blocked when no allowed_network is configured.
    // =========================================================================
    println!("{}--- Scenario 1: no policy (deny-by-default){}", CYAN, RESET);
    let mut mgr = load_plugin(&shared, None, "net-deny-all").await;
    let r = invoke(&mut mgr, "https://example.com/", "GET").await;
    print_case("DENY expected", "GET", "https://example.com/", &r);
    println!();

    // =========================================================================
    // Scenario 2: Host allowlist
    // example.com is explicitly allowed; other.com is not in the list.
    // =========================================================================
    println!("{}--- Scenario 2: host allowlist  allowed=[example.com]{}", CYAN, RESET);
    let policy = SandboxPolicy {
        allowed_network: vec![NetworkRule {
            host: "example.com".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut mgr = load_plugin(&shared, Some(policy), "net-allowlist").await;
    let r = invoke(&mut mgr, "https://example.com/", "GET").await;
    print_case("ALLOW expected", "GET", "https://example.com/", &r);
    let r = invoke(&mut mgr, "https://other.com/", "GET").await;
    print_case("DENY expected",  "GET", "https://other.com/",  &r);
    println!();

    // =========================================================================
    // Scenario 3: Wildcard host
    // *.example.com matches api.example.com and data.example.com,
    // but NOT the apex example.com itself.
    // =========================================================================
    println!("{}--- Scenario 3: wildcard host  allowed=[*.example.com]{}", CYAN, RESET);
    let policy = SandboxPolicy {
        allowed_network: vec![NetworkRule {
            host: "*.example.com".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut mgr = load_plugin(&shared, Some(policy), "net-wildcard").await;
    let r = invoke(&mut mgr, "https://api.example.com/", "GET").await;
    print_case("ALLOW expected", "GET", "https://api.example.com/",  &r);
    let r = invoke(&mut mgr, "https://data.example.com/", "GET").await;
    print_case("ALLOW expected", "GET", "https://data.example.com/", &r);
    let r = invoke(&mut mgr, "https://example.com/", "GET").await;
    print_case("DENY expected",  "GET", "https://example.com/",      &r);
    println!();

    // =========================================================================
    // Scenario 4: Port enforcement
    // Only port 443 is allowed. Port 8080 must be denied.
    // =========================================================================
    println!("{}--- Scenario 4: port enforcement  allowed_ports=[443]{}", CYAN, RESET);
    let policy = SandboxPolicy {
        allowed_network: vec![NetworkRule {
            host: "example.com".to_string(),
            ports: vec![443],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut mgr = load_plugin(&shared, Some(policy), "net-port").await;
    let r = invoke(&mut mgr, "https://example.com/", "GET").await;
    print_case("ALLOW expected", "GET", "https://example.com/       (port 443, implicit)", &r);
    let r = invoke(&mut mgr, "https://example.com:8080/", "GET").await;
    print_case("DENY expected",  "GET", "https://example.com:8080/  (port 8080)", &r);
    println!();

    // =========================================================================
    // Scenario 5: Scheme enforcement
    // Default schemes = ["https"] — plain http must be denied.
    // =========================================================================
    println!("{}--- Scenario 5: scheme enforcement  allowed_schemes=[https]{}", CYAN, RESET);
    let policy = SandboxPolicy {
        allowed_network: vec![NetworkRule {
            host: "example.com".to_string(),
            // schemes defaults to ["https"]
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut mgr = load_plugin(&shared, Some(policy), "net-scheme").await;
    let r = invoke(&mut mgr, "https://example.com/", "GET").await;
    print_case("ALLOW expected", "GET", "https://example.com/  (https)", &r);
    let r = invoke(&mut mgr, "http://example.com/", "GET").await;
    print_case("DENY expected",  "GET", "http://example.com/   (http)", &r);
    println!();

    // =========================================================================
    // Scenario 6: Method enforcement
    // Only GET is allowed. POST must be denied.
    // =========================================================================
    println!("{}--- Scenario 6: method enforcement  allowed_methods=[GET]{}", CYAN, RESET);
    let policy = SandboxPolicy {
        allowed_network: vec![NetworkRule {
            host: "example.com".to_string(),
            methods: vec!["GET".to_string()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut mgr = load_plugin(&shared, Some(policy), "net-method").await;
    let r = invoke(&mut mgr, "https://example.com/", "GET").await;
    print_case("ALLOW expected", "GET",  "https://example.com/", &r);
    let r = invoke(&mut mgr, "https://example.com/", "POST").await;
    print_case("DENY expected",  "POST", "https://example.com/", &r);
    println!();

    // =========================================================================
    // Scenario 7: Multi-rule — two hosts with different constraints
    // api.example.com: GET only on port 443
    // data.example.com: GET+POST on ports 443 and 8443
    // other.com: not listed — denied
    // =========================================================================
    println!("{}--- Scenario 7: multi-rule  [api.example.com GET:443]  [data.example.com GET+POST:443,8443]{}", CYAN, RESET);
    let policy = SandboxPolicy {
        allowed_network: vec![
            NetworkRule {
                host: "api.example.com".to_string(),
                ports: vec![443],
                methods: vec!["GET".to_string()],
                ..Default::default()
            },
            NetworkRule {
                host: "data.example.com".to_string(),
                ports: vec![443, 8443],
                methods: vec!["GET".to_string(), "POST".to_string()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let mut mgr = load_plugin(&shared, Some(policy), "net-multi").await;
    let r = invoke(&mut mgr, "https://api.example.com/", "GET").await;
    print_case("ALLOW expected", "GET",  "https://api.example.com/",       &r);
    let r = invoke(&mut mgr, "https://api.example.com/", "POST").await;
    print_case("DENY expected",  "POST", "https://api.example.com/",       &r);
    let r = invoke(&mut mgr, "https://data.example.com/", "POST").await;
    print_case("ALLOW expected", "POST", "https://data.example.com/",      &r);
    let r = invoke(&mut mgr, "https://data.example.com:8443/", "GET").await;
    print_case("ALLOW expected", "GET",  "https://data.example.com:8443/", &r);
    let r = invoke(&mut mgr, "https://other.com/", "GET").await;
    print_case("DENY expected",  "GET",  "https://other.com/",             &r);
    println!();

    println!("{}=== Demo complete ==={}\n", BOLD, RESET);
}
