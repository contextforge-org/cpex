# quickstart instructions - Installing and runing existing Python CPEX plugins out-of-process from the Rust PolicyEngine

## First steps
- create a folder to setup CPEX (Rust) + (Pythyon)
```bash
mkdir -p code-review/python-tests && cd code-review/python-tests
```

## Installing CPEX python
```bash
   # /bin/bash
   pyenv shell 3.13.5
   python -m venv .venv
   source .venv/bin/activate
   # pip install cpex ( cpex 0.1.4 has not yet been released)
   pip install git+https://github.com/contextforge-org/cpex.git@0.1.x
   echo "PLUGINS_GITHUB_TOKEN=<your_github_token>" > .env
   mkdir plugins
   # install a python plugin using the python cpex cli
   cpex plugin --type monorepo install cpex-pii-filter
   # Now install the cpex dependency (0.1.4 unreleased) into the isolated venv of the plugin
   deactivate
   source plugins/cpex_pii_filter/.venv/bin/activate
   pip install git+https://github.com/contextforge-org/cpex.git@0.1.x
```


Expected filesystem tree (relative to the project root where cpex 2.0 is installed)

```bash
├── .venv
├── data
├── plugin-catalog
│   ├── cpex-encoded-exfil-detection
│   ├── cpex-pii-filter
│   ├── cpex-plugins
│   ├── cpex-rate-limiter
│   ├── cpex-retry-with-backoff
│   ├── cpex-secrets-detection
│   ├── cpex-sql-sanitizer
│   └── cpex-url-reputation
└── plugins
    └── cpex_pii_filter
        ├── .cpex
        └── .venv
```

## Installing CPEX (Rust)

```bash
cargo init
cargo add cpex --features python-host  --git https://github.com/contextforge-org/cpex.git --branch dev
cargo add tokio --features full
cargo add serde_json

```

## Adapting the installer-written config

`cpex plugin install` writes `plugins/config.yaml` in the pre-PPE shape. Make
three edits before loading it:

- Delete the top-level `plugin_dirs:` key. PPE rejects it; the host always uses
  `plugins/` at the project root.
- Add `engine_settings:` with `dispatch: hooks`, so each plugin fires at the
  hooks it declares without a `routes:` or `authorization:` block.
- Rename the hooks in any `hooks:` list to PPE's names: `tool_pre_invoke` to
  `cmf.tool_pre_invoke`, `identity_resolve` to `identity.resolve`, and
  `token_delegate` to `token.delegate`. The host translates them back to the
  names the Python worker knows.

The plugin itself needs no change. The 0.1.x worker registers no `cmf.*` hooks,
so the host serves `cmf.tool_pre_invoke` to it through the legacy payload shim:
the plugin's `tool_pre_invoke` receives the usual `ToolPreInvokePayload`
(`name` plus `args`), and a modified payload maps back onto the CMF message.
See the README's "legacy payload shim" section for every hook it covers. A
message that carries text beside the tool call fails closed there, since the
legacy plugin would never see that text.

An identity or delegation plugin also needs no change. On `identity.resolve`
and `token.delegate` it receives the `IdentityPayload` / `DelegationPayload` it
already reads, and its `IdentityResult` / `DelegationResult` maps back onto
PPE's payload. To receive the raw token it declares `read_inbound_credentials`
on either hook (the bearer token a delegator exchanges is the caller's inbound
credential).

## Example driver program (replaces code-review/python-tests/src/main.rs)

```rust
use std::path::{PathBuf};
use std::sync::Arc;
use std::collections::HashMap;
use cpex::PolicyEngine;
use cpex::praxis_policy_core::factory::PluginFactoryRegistry;
use cpex::praxis_policy_core::config::parse_config;
use cpex::praxis_policy_core::error::PluginError;
use cpex::praxis_policy_core::extensions::{
    AgentExtension, Extensions, HttpExtension, RequestExtension, SecurityExtension,
};
use cpex::cpex_hosts_python::{IsolatedVenvFactory, KIND};
use cpex::praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};

/// Marker `TestPlugin.identity_resolve` writes when `raw_token` arrives with a
/// non-empty secret value — evidence the field survived the wire as a populated
/// `SecretStr` rather than as `None` or an empty string.
const IDENTITY_RAW_TOKEN_MARKER: &str = "identity_resolve_raw_token";

/// Marker `TestPlugin.token_delegate` writes when `bearer_token` arrives with a
/// non-empty secret value. See [`IDENTITY_RAW_TOKEN_MARKER`].
const TOKEN_DELEGATE_BEARER_MARKER: &str = "token_delegate_bearer_token";

/// A security label on the inbound extensions. Distinctive so an assertion on it
/// cannot pass against a default-constructed `Extensions`.
const INBOUND_LABEL: &str = "CONFIG-E2E-LABEL-4f18";

/// A header value that must never cross the process boundary. Asserted by
/// absence from the serialized task, so it has to be unique enough that a match
/// anywhere in the JSON is conclusive.
const SENSITIVE_HEADER_VALUE: &str = "Bearer config-e2e-must-not-travel";
/// The PPE hook the driver dispatches. The installed plugin implements the
/// legacy `tool_pre_invoke`, which the host reaches through the shim.
const TOOL_PRE_INVOKE: &str = "cmf.tool_pre_invoke";

/// The project root. `plugins/config.yaml` and the installed plugin live under it.
fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = ./
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .to_path_buf()
}

fn inbound_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label(INBOUND_LABEL);
    security.classification = Some("internal".to_string());
    security.auth_method = Some("jwt".to_string());

    let mut http = HttpExtension::default();
    http.set_request_header("Authorization", SENSITIVE_HEADER_VALUE);
    http.set_request_header("X-Request-Id", "req-config-e2e-1");
    http.method = Some("POST".to_string());
    http.path = Some("/rpc/tools/invoke".to_string());

    Extensions {
        request: Some(Arc::new(RequestExtension {
            environment: Some("test".to_string()),
            request_id: Some("req-config-e2e-1".to_string()),
            trace_id: Some("trace-config-e2e-1".to_string()),
            ..Default::default()
        })),
        agent: Some(Arc::new(AgentExtension {
            session_id: Some("session-config-e2e".to_string()),
            agent_id: Some("agent-config-e2e".to_string()),
            turn: Some(3),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        custom: Some(Arc::new(HashMap::from([(
            "config_e2e".to_string(),
            serde_json::json!({"source": "config_e2e.rs"}),
        )]))),
        ..Default::default()
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sets the project root the host resolves `plugins` against and the worker's
    // cwd at once — see the comment in the test above.
    let root = repo_root();
    std::env::set_current_dir(&root).expect("cd to the repo root");
    let config_path = root.join("plugins").join("config.yaml");
    let yaml = std::fs::read_to_string(&config_path).map_err(|e| PluginError::Config {
        message: format!("failed to read config file '{}': {}", config_path.display(), e),
    })?;
    let config = parse_config(&yaml)?;
    let mut factories = PluginFactoryRegistry::new();
    factories.register(KIND, Box::new(IsolatedVenvFactory));

    let manager = PolicyEngine::from_config(config, &factories)?;
    manager
        .initialize()
        .await
        .expect("the venv resolves and the worker starts");

    // A CMF tool call. The host turns it into the `name` plus `args` payload
    // the plugin's legacy `tool_pre_invoke` expects.
    let payload = MessagePayload {
        message: Message::with_content(
            Role::Assistant,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-1".to_string(),
                    name: "test_tool".to_string(),
                    arguments: HashMap::from([(
                        "query".to_string(),
                        serde_json::json!("hello world"),
                    )]),
                    namespace: None,
                },
            }],
        ),
    };

    // Populated extensions rather than `Extensions::default()`. The default is
    // the one input that cannot fail: with every slot `None`,
    // `attach_extensions` writes no field at all, so the whole inbound channel
    // is untested and the assertions below hold vacuously. Passing real slots
    // through the installer-written config is what makes this test cover the
    // channel — see `inbound_extensions` for what each slot is there to prove.
    let inbound = inbound_extensions();

    let (result, _background) = manager
        .invoke_by_name(
            TOOL_PRE_INVOKE,
            Box::new(payload),
            inbound.clone(),
            None,
        )
        .await;

    manager.shutdown().await;

    println!(
        "allowed={} errors={:?} violation={:?}",
        result.continue_processing, result.errors, result.violation
    );
    Ok(())
}
```

## Building and running

### Building
```bash
cargo build
```

### Running

```bash
cargo run
```