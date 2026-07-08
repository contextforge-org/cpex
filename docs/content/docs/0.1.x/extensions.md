---
title: "Extensions & Capabilities"
weight: 60
---

# Extensions & Capabilities

Extensions carry typed contextual metadata — identity, security labels, HTTP headers, delegation chains — through the plugin pipeline. The capability system controls which plugins can see and modify which extension slots.

---

## The Extensions Container

`Extensions` is a frozen Pydantic model that attaches to payloads flowing through the pipeline. Each field is an optional typed slot:

```python
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.request import RequestExtension
from cpex.framework.extensions.security import SecurityExtension

ext = Extensions(
    request=RequestExtension(environment="production", request_id="req-001"),
    security=SecurityExtension(labels=frozenset({"pii", "confidential"})),
)

ext.request.environment   # "production"
ext.security.labels        # frozenset({"pii", "confidential"})
ext.http                   # None — not populated
```

Extensions are frozen. To modify, use `model_copy(update={...})`:

```python
updated = ext.model_copy(update={"custom": {"trace_id": "abc-123"}})
```

---

## Extension Slots

| Slot | Type | Description | Access |
|------|------|-------------|--------|
| `request` | `RequestExtension` | Environment, request ID, timestamp, tracing | Unrestricted |
| `agent` | `AgentExtension` | Session tracking, multi-agent lineage | `read_agent` |
| `http` | `HttpExtension` | HTTP headers | `read_headers` / `write_headers` |
| `security` | `SecurityExtension` | Labels, classification, subject identity | Mixed (see below) |
| `delegation` | `DelegationExtension` | Token delegation chain | `read_delegation` / `append_delegation` |
| `mcp` | `MCPExtension` | Tool, resource, or prompt metadata | Unrestricted |
| `completion` | `CompletionExtension` | Stop reason, token usage, model, latency | Unrestricted |
| `provenance` | `ProvenanceExtension` | Source, message ID, parent ID | Unrestricted |
| `llm` | `LLMExtension` | Model identity and capabilities | Unrestricted |
| `framework` | `FrameworkExtension` | Agentic framework context | Unrestricted |
| `meta` | `MetaExtension` | Host-provided operational metadata | Unrestricted |
| `custom` | `dict[str, Any]` | Free-form plugin data | Unrestricted |

**Unrestricted** slots are visible to all plugins. **Capability-gated** slots require a declared capability.

---

## Mutability Tiers

Each extension slot has a mutability tier that the pipeline enforces:

| Tier | Rule | Example |
|------|------|---------|
| **Immutable** | Set once, never changed. Pipeline rejects any delta. | `request`, `provenance`, `agent` |
| **Monotonic** | Can only grow — elements can be added, never removed. Pipeline validates `before ⊆ after`. | `security.labels`, `delegation.chain` |
| **Mutable** | Freely modifiable via copy-on-write. | `custom` |

---

## Capabilities

Capabilities are declared in the plugin's YAML config and control what a plugin can access:

```yaml
plugins:
  - name: header_injector
    kind: my_app.HeaderInjectorPlugin
    hooks:
      - tool_pre_invoke
    mode: sequential
    capabilities:
      - read_headers
      - write_headers
```

Available capabilities:

| Capability | Grants |
|-----------|--------|
| `read_subject` | Read subject ID and type |
| `read_roles` | Read subject roles (implies `read_subject`) |
| `read_teams` | Read subject teams (implies `read_subject`) |
| `read_claims` | Read subject claims (implies `read_subject`) |
| `read_permissions` | Read subject permissions (implies `read_subject`) |
| `read_agent` | Read agent extension |
| `read_headers` | Read HTTP headers |
| `write_headers` | Read + write HTTP headers |
| `read_labels` | Read security labels |
| `append_labels` | Read + append security labels (monotonic) |
| `read_delegation` | Read delegation chain |
| `append_delegation` | Read + append delegation chain (monotonic) |

Write capabilities imply their corresponding read capability. A plugin with `write_headers` can also read headers.

---

## How It Works

The framework applies two filters around every plugin execution:

1. **Before** — `filter_extensions()` builds a new `Extensions` containing only the slots the plugin has access to. Slots the plugin can't see are `None`.
2. **After** — `merge_extensions()` accepts back only the changes the plugin was authorized to make. Immutable slots are ignored. Monotonic slots are validated for growth. Unauthorized writes are silently discarded.

This means plugins can't even *see* data they lack capabilities for, and they can't sneak in unauthorized changes.

---

## Accepting Extensions in a Hook

Add a third parameter to your hook signature:

```python
from cpex.framework import hook, Plugin, PluginContext, PluginResult, ToolPreInvokePayload, ToolPreInvokeResult
from cpex.framework.extensions.extensions import Extensions


class HeaderInspectorPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def inspect_headers(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions: Extensions,
    ) -> ToolPreInvokeResult:
        if extensions.http:
            auth = extensions.http.headers.get("authorization", "none")
            context.set_state("auth_method", auth.split()[0] if " " in auth else auth)
        return ToolPreInvokeResult(continue_processing=True)
```

The framework detects the 3-parameter signature automatically and passes the capability-filtered extensions.

---

## Returning Modified Extensions

To modify extensions, return `modified_extensions` in the result:

```python
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.http import HttpExtension


class TokenDelegationPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def delegate_token(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions: Extensions,
    ) -> ToolPreInvokeResult:
        delegated_token = await self._exchange_token(extensions)

        updated_http = HttpExtension(
            headers={**(extensions.http.headers if extensions.http else {}),
                     "authorization": f"Bearer {delegated_token}"},
        )
        updated_ext = extensions.model_copy(update={"http": updated_http})

        return ToolPreInvokeResult(
            continue_processing=True,
            modified_extensions=updated_ext,
        )
```

The manager merges only the fields the plugin is authorized to write. In this case, the plugin needs `write_headers` in its capabilities.

---

## Security Sub-Field Gating

The `security` extension has granular sub-field access control. A plugin with `read_roles` can see `security.subject.roles` but not `security.subject.claims`:

```yaml
capabilities:
  - read_roles
  - read_labels
```

This plugin sees:
- `security.subject.id` and `security.subject.type` (implied by `read_roles`)
- `security.subject.roles` (granted by `read_roles`)
- `security.labels` (granted by `read_labels`)
- `security.objects`, `security.data`, `security.classification` (always unrestricted)

It does **not** see:
- `security.subject.teams`, `security.subject.claims`, `security.subject.permissions`
