// =========================================================================
// sampleWasmPlugin — Reference CPEX WASM plugin in Rust
// =========================================================================
//
// Builds with `cargo component build --release` into a Component Model
// .wasm artifact that satisfies the contextforge:cpex@0.1.0 `plugin` world.
//
// What this example does
// ----------------------
// On `tool_pre_invoke`, it inspects `payload.name` and blocks any tool
// whose name appears in `config.blocked_tools`. On `tool_post_invoke`, it
// passes through. Everything else returns "continue, no changes".
//
// Why JSON in/out
// ---------------
// See docs/specs/wasm-plugin-spec.md §3.1. The short version: JSON is the
// shared wire format across all CPEX out-of-process plugin kinds, so the
// host doesn't need wasm-specific serialization, and this artifact remains
// portable across future host language reimplementations.
// =========================================================================

#![allow(clippy::module_name_repetitions)]

// wit-bindgen generates the Guest trait, types, and import stubs from
// wit/cpex-plugin.wit. The `export!` macro at the bottom wires our impl
// into the component's export table.
wit_bindgen::generate!({
    world: "plugin",
    path: "wit",
});

use std::cell::RefCell;
use std::collections::HashSet;

use contextforge::cpex::types::LogLevel;
use contextforge::cpex::{clock, logging};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// Plugin state
// ---------------------------------------------------------------------
// Components are instantiated fresh per CPEX `WasmPlugin`. The Store is
// single-threaded, so a `RefCell<thread_local!>` is the idiomatic place
// to hold mutable plugin state across hook calls.

thread_local! {
    static STATE: RefCell<PluginState> = RefCell::new(PluginState::default());
}

#[derive(Default)]
struct PluginState {
    blocked_tools: HashSet<String>,
    initialized: bool,
}

// ---------------------------------------------------------------------
// Config schema (mirrors plugin-manifest.yaml's config_schema)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PluginInitConfig {
    #[serde(default)]
    blocked_tools: Vec<String>,
}

// ---------------------------------------------------------------------
// Hook payload schemas — mirror cpex's Pydantic models
// ---------------------------------------------------------------------
// We deserialize only the fields we care about. `#[serde(default)]` on
// the rest means future host-side additions don't break us.

#[derive(Debug, Deserialize)]
struct ToolPreInvokePayload {
    name: String,
    #[serde(default)]
    args: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ToolPostInvokePayload {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    result: serde_json::Value,
}

// PluginResult is constructed on the way back. We model only what we set;
// `continue_processing` defaults to true if omitted in JSON, matching
// host-side Pydantic.

#[derive(Debug, Serialize)]
struct PluginViolation {
    reason: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct PluginResultOut {
    continue_processing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    violation: Option<PluginViolation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_payload: Option<serde_json::Value>,
}

impl PluginResultOut {
    fn allow() -> Self {
        Self {
            continue_processing: true,
            violation: None,
            modified_payload: None,
        }
    }

    fn block(code: &str, reason: &str, details: Option<serde_json::Value>) -> Self {
        Self {
            continue_processing: false,
            violation: Some(PluginViolation {
                reason: reason.to_string(),
                code: code.to_string(),
                details,
            }),
            modified_payload: None,
        }
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn err(code: &str, message: &str) -> PluginError {
    PluginError {
        code: code.into(),
        message: message.into(),
        retryable: false,
    }
}

fn log_info(msg: &str) {
    // logging is always granted; calling this is safe regardless of manifest.
    logging::log(LogLevel::Info, msg);
}

// ---------------------------------------------------------------------
// World implementation
// ---------------------------------------------------------------------

struct Component;

impl Guest for Component {
    fn init(config_json: String) -> Result<(), PluginError> {
        let cfg: PluginInitConfig = serde_json::from_str(&config_json)
            .map_err(|e| err("CONFIG_PARSE_ERROR", &format!("bad init config: {e}")))?;

        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.blocked_tools = cfg.blocked_tools.into_iter().collect();
            s.initialized = true;
        });

        log_info(&format!(
            "samplewasmplugin initialized at {}ms",
            clock::now_millis()
        ));
        Ok(())
    }

    fn manifest() -> ManifestInfo {
        ManifestInfo {
            name: "samplewasmplugin".into(),
            version: "0.1.0".into(),
            api_version: "cpex.plugin/v1".into(),
            hooks: vec!["tool_pre_invoke".into(), "tool_post_invoke".into()],
            required_capabilities: vec!["log".into(), "clock".into()],
        }
    }

    fn invoke_hook(
        hook_name: String,
        payload_json: String,
        _context_json: String,
    ) -> Result<String, PluginError> {
        let initialized = STATE.with(|s| s.borrow().initialized);
        if !initialized {
            return Err(err("NOT_INITIALIZED", "init() was never called"));
        }

        let result = match hook_name.as_str() {
            "tool_pre_invoke" => handle_tool_pre_invoke(&payload_json)?,
            "tool_post_invoke" => handle_tool_post_invoke(&payload_json)?,
            other => {
                return Err(err(
                    "UNKNOWN_HOOK",
                    &format!("plugin does not handle hook {other:?}"),
                ));
            }
        };

        serde_json::to_string(&result)
            .map_err(|e| err("SERIALIZE_ERROR", &format!("could not encode result: {e}")))
    }

    fn shutdown() {
        log_info("samplewasmplugin shutting down");
    }
}

// ---------------------------------------------------------------------
// Hook handlers
// ---------------------------------------------------------------------

fn handle_tool_pre_invoke(payload_json: &str) -> Result<PluginResultOut, PluginError> {
    let payload: ToolPreInvokePayload = serde_json::from_str(payload_json)
        .map_err(|e| err("PAYLOAD_PARSE_ERROR", &format!("bad tool payload: {e}")))?;

    let blocked = STATE.with(|s| s.borrow().blocked_tools.contains(&payload.name));
    if blocked {
        return Ok(PluginResultOut::block(
            "TOOL_BLOCKED",
            &format!("tool {:?} is blocked by policy", payload.name),
            Some(serde_json::json!({ "tool": payload.name })),
        ));
    }
    Ok(PluginResultOut::allow())
}

fn handle_tool_post_invoke(_payload_json: &str) -> Result<PluginResultOut, PluginError> {
    Ok(PluginResultOut::allow())
}

// Export `Component` as the implementor of the `plugin` world.
export!(Component);
