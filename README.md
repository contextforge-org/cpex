<div>
  <img alt="ContextForge Plugin Extensibility Framework (CPEX) logo" src="https://github.com/contextforge-org/contextforge-plugins-framework/blob/main/docs/images/cpex_v1.png?raw=true" height=100">
</div>

# CPEX — ContextForge Plugin Extensibility Framework

<i>A composable enforcement framework for AI agents and toolchains.</i>

[![CI](https://github.com/contextforge-org/contextforge-plugins-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/contextforge-org/contextforge-plugins-framework/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/cpex.svg?color=blue)](https://pypi.org/project/cpex)

> [**Read the project vision**](https://contextforge-org.github.io/contextforge-plugins-framework/docs/vision/) to learn why hooks, plugins, and policy are the path to agent security.

## What's CPEX?

CPEX lets you intercept, enforce, and extend application behavior through plugins without modifying core logic.

Define hook points in your application, write plugins that attach to them, and compose enforcement pipelines that run automatically.

```python
from cpex.framework import hook, Plugin, PluginResult

class RateLimitPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def check_rate_limit(self, payload, context):
        if self.is_over_limit(context):
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(reason="Rate limit exceeded", code="RATE_LIMIT")
            )
        return PluginResult(continue_processing=True)
```

Register the plugin, and it runs at every hook invocation. No changes to your application logic.

## Install

```bash
pip install cpex
```

## Why CPEX?

AI agents execute across trust domains, calling tools, accessing data, and delegating to other agents. Adding security, governance, or policy enforcement typically means embedding that logic directly into application code, leading to duplication, tight coupling, and drift.

CPEX introduces **standardized interception hooks** between your application and its operations. Plugins attach to these hooks and run automatically, keeping enforcement logic separate from business logic.

**What you can build with CPEX:**

- **Security** — access control, prompt injection detection, data loss prevention
- **Observability** — request tracing, audit logging, metrics collection
- **Governance** — policy enforcement, compliance validation, approval workflows
- **Reliability** — rate limiting, circuit breakers, response validation

CPEX is designed for modern **AI and agent systems**, but works equally well for any application that needs **safe, modular extensibility**.

## How It Works

Your application defines **hooks** — named interception points before and after critical operations. Plugins register against these hooks and execute automatically when triggered.

```
Application  →  Hook Point  →  Plugin Manager  →  Application (remaining processing)  →  Result
                                     │
                              ┌──────┼──────┐
                              ▼      ▼      ▼
                          Plugin  Plugin  Plugin
```

The plugin manager handles registration, ordering, execution, timeouts, and error isolation. You get a deterministic pipeline with no surprises.

## Core Concepts

### Hooks

A hook is a named interception point in your application. You define a hook where you want plugins to be able to run, then call it there.

**Define hook models:**

```python
from cpex.framework import PluginPayload, PluginResult

class EmailPayload(PluginPayload):
    recipient: str
    subject: str
    body: str

EmailResult = PluginResult[EmailPayload]
```

**Register it:**

```python
from cpex.framework.hooks.registry import get_hook_registry

registry = get_hook_registry()
registry.register_hook("email_pre_send", EmailPayload, EmailResult)
```

**Call the hook in your application:**

```python
async def send_email(recipient: str, subject: str, body: str):
    payload = EmailPayload(recipient=recipient, subject=subject, body=body)
    context = GlobalContext(request_id="req-123")

    result, _ = await manager.invoke_hook("email_pre_send", payload, context)

    if not result.continue_processing:
        raise PolicyError(result.violation.reason)

    # proceed with sending
    await smtp.send(payload.recipient, payload.subject, payload.body)
```

CPEX also ships with built-in hooks for common AI operations (`tool_pre_invoke`, `tool_post_invoke`, `prompt_pre_fetch`, `prompt_post_fetch`, `resource_pre_fetch`, `resource_post_fetch`, `agent_pre_invoke`, `agent_post_invoke`). These follow the same pattern and are ready to use without registration.

### Plugins

A plugin is a class that implements one or more hook handlers. Use the `@hook` decorator to attach a method to any hook by name:

```python
from cpex.framework import hook, Plugin, PluginViolation, PluginResult

class EmailFilterPlugin(Plugin):
    @hook("email_pre_send")
    async def block_external_domains(self, payload: EmailPayload, context) -> PluginResult:
        allowed = self.config.config.get("allowed_domains", [])
        domain = payload.recipient.split("@")[-1]

        if allowed and domain not in allowed:
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Domain not allowed",
                    code="DOMAIN_BLOCKED",
                    details={"domain": domain}
                )
            )

        return PluginResult(continue_processing=True)
```

The `@hook` decorator decouples method names from hook names, which is useful when a plugin handles multiple hooks or when names would otherwise conflict.

For built-in hooks, you can also use the naming convention directly (method name matches hook name) without a decorator:

```python
class ContentFilterPlugin(Plugin):
    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        blocked = self.config.config.get("blocked_tools", [])
        if payload.name in blocked:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(reason="Tool blocked by policy", code="TOOL_BLOCKED")
            )
        return ToolPreInvokeResult(continue_processing=True)
```

A plugin method can:

- **Allow** execution to continue
- **Block** execution with a violation
- **Modify** the payload (using copy-on-write isolation)

### Execution Modes

Plugins run in phases in this order:

```
sequential → transform → audit → concurrent → fire_and_forget
```

| Mode | Execution | Can block? | Can modify? | State merged? | Use case |
|------|-----------|:-----------:|:-----------:|:-------------:|---------|
| `sequential` | Serial, chained | Yes | Yes | Yes | Policy enforcement + transformation |
| `transform` | Serial, chained | No | Yes | Yes | Data transformation (redaction, rewriting) |
| `audit` | Serial | No | No | No | Logging, monitoring, metrics |
| `concurrent` | Parallel, fail-fast | Yes | No | Yes | Independent policy gates |
| `fire_and_forget` | Background, after all phases | No | No | No | Telemetry, audit logs |
| `disabled` | Not loaded | — | — | — | Plugin off |

- **`sequential`** plugins are awaited one at a time in priority order. Each receives the chained output of the previous plugin. Can halt the pipeline and modify payloads. Use for enforcement + transformation.
- **`transform`** plugins are awaited one at a time after all sequential plugins. Can modify payloads but blocking attempts are suppressed. Use for data transformation pipelines (PII redaction, prompt rewriting) that should not have policy-enforcement power.
- **`audit`** plugins are awaited one at a time after transform. Observe-only: payload modifications are discarded and violations are logged but do not block. Use for monitoring, auditing, and gradual rollout of policies.
- **`concurrent`** plugins are dispatched in parallel after audit. Can halt the pipeline (fail-fast on first blocking result) but payload modifications are discarded to avoid non-deterministic last-writer-wins races. Use for independent policy gates.
- **`fire_and_forget`** plugins are dispatched as background tasks after all other phases. They receive an isolated snapshot. Cannot block or modify. Use for telemetry and async side effects.

Error handling is configured separately with `on_error`, independent of mode:

| `on_error` | Behavior |
|-----------|---------|
| `fail` | Pipeline halts, error propagates (default) |
| `ignore` | Error logged; pipeline continues |
| `disable` | Error logged; plugin auto-disabled; pipeline continues |

### Plugin Manager

The `PluginManager` orchestrates everything:

```python
from cpex.framework import PluginManager, GlobalContext
from cpex.framework.hooks.tools import ToolPreInvokePayload

manager = PluginManager("plugins/config.yaml")
await manager.initialize()

context = GlobalContext(request_id="req-123", user="alice")
payload = ToolPreInvokePayload(name="web_search", args={"query": "CPEX framework"})

result, plugin_contexts = await manager.invoke_hook("tool_pre_invoke", payload, context)

if result.continue_processing:
    # Proceed — use result.modified_payload if a plugin transformed it
    pass
else:
    # A plugin blocked execution
    print(f"Blocked: {result.violation.reason}")
```

## Configuration

Plugins are configured in YAML:

```yaml
plugin_dirs:
  - ./plugins

plugins:
  - name: email_filter
    kind: my_app.plugins.EmailFilterPlugin
    version: 1.0.0
    hooks:
      - email_pre_send
    mode: sequential
    priority: 10
    config:
      allowed_domains:
        - company.com
        - partner.org
```

### Priority

Plugins are scheduled by mode, and execute in priority order within each phase (lower number = higher priority). Use this to ensure enforcement runs before transformation, and transformation runs before logging.

**Plugin Scheduling**

At each hook invocation, plugins are grouped and scheduled by execution mode, following a strict phase order:

```
sequential → transform → audit → concurrent → fire_and_forget
```

Within `sequential`, `transform`, and `audit` phases, plugins execute in **priority order** (lower number = higher priority, e.g., `10` runs before `20`).

### Conditions

Restrict plugins to specific contexts:

```yaml
plugins:
  - name: tenant_plugin
    kind: my_app.plugins.TenantPlugin
    hooks:
      - tool_pre_invoke
    mode: sequential
    conditions:
      - tenant_ids: [tenant-1, tenant-2]
        server_ids: [server-prod]
```

## Testing

Plugins are plain async classes — test them directly:

```python
import pytest
from cpex.framework import PluginConfig, GlobalContext, PluginContext

@pytest.mark.asyncio
async def test_email_filter_blocks_external_domain():
    config = PluginConfig(
        name="test_filter",
        kind="my_app.plugins.EmailFilterPlugin",
        version="1.0.0",
        hooks=["email_pre_send"],
        config={"allowed_domains": ["company.com"]}
    )
    plugin = EmailFilterPlugin(config)

    payload = EmailPayload(recipient="user@external.com", subject="Hello", body="...")
    context = PluginContext(global_context=GlobalContext(request_id="test-1"))

    result = await plugin.block_external_domains(payload, context)
    assert result.continue_processing is False
    assert result.violation.code == "DOMAIN_BLOCKED"
```

## External Plugins

Plugins can run as standalone services, connected over MCP (Streamable HTTP), gRPC, or Unix domain sockets.

```yaml
plugins:
  - name: remote_validator
    kind: external
    hooks:
      - tool_pre_invoke
    mode: sequential
    mcp:
      proto: STREAMABLEHTTP
      url: https://plugin-server.example.com
      tls:
        certfile: /path/to/client-cert.pem
        keyfile: /path/to/client-key.pem
        ca_bundle: /path/to/ca-bundle.pem
```

Build an external plugin server with the built-in `ExternalPluginServer`:

```python
from cpex.framework import ExternalPluginServer

server = ExternalPluginServer(plugins=[MyPlugin(config)])
server.run()
```

## Isolated plugins

Native plugins can be run in a separate python virtual environment (venv) to prevent them from interfering with the host environment.  Plugin specific packages are automatically installed based on the contents of the supplied requirements_file.  

```yaml
  - name: "test_plugin"
    kind: "isolated_venv"
    version: "0.1.0"
    hooks: ["prompt_pre_fetch", "prompt_post_fetch", "tool_pre_invoke", "tool_post_invoke"]
    tags: ["plugin"]
    mode: "sequential"
    priority: 150
    conditions:
      # Apply to specific tools/servers
      - server_ids: []  # Apply to all servers
        tenant_ids: []  # Apply to all tenants
    config:
      # Plugin config dict passed to the plugin constructor
      class_name: "test_plugin.plugin.TestPlugin"
      requirements_file: "requirements.txt"
      # essentially the plugin folder hosting the plugin relative to the project root
      script_path: "plugins"
```


## Project Status

CPEX is under active development as part of the [ContextForge](https://github.com/contextforge-org) ecosystem. The framework is designed to work across AI gateways, agent frameworks, LLM proxies, and tool servers.

## Contributing

Contributions are welcome. Open an issue, propose a plugin, or submit a pull request.

## License

[Apache 2.0](LICENSE)
