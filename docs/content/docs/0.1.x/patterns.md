---
title: "Patterns & Best Practices"
weight: 110
---

# Patterns & Best Practices

Curated patterns for building production plugin pipelines.

---

## Layered Security Pipeline

Compose modes and priorities to build defense-in-depth. Each layer has a specific responsibility:

```yaml
plugins:
  # Layer 1: hard enforcement — blocks requests that violate policy
  - name: token_budget
    kind: security.TokenBudgetPlugin
    mode: sequential
    priority: 10
    hooks: [tool_pre_invoke]

  # Layer 2: content policy — blocks prohibited content
  - name: content_policy
    kind: security.ContentPolicyPlugin
    mode: sequential
    priority: 20
    hooks: [tool_pre_invoke, agent_pre_invoke]

  # Layer 3: transformation — redacts PII without blocking
  - name: pii_redactor
    kind: privacy.PIIRedactionPlugin
    mode: transform
    priority: 30
    hooks: [tool_pre_invoke, tool_post_invoke]

  # Layer 4: background logging — never blocks or slows
  - name: audit_logger
    kind: observability.AuditLogPlugin
    mode: fire_and_forget
    priority: 100
    hooks: [tool_pre_invoke, tool_post_invoke, prompt_pre_fetch]
```

Execution order: `token_budget` (sequential) → `content_policy` (sequential) → `pii_redactor` (transform) → `audit_logger` (fire_and_forget). Each layer can only do what its mode permits.

---

## Graceful Policy Rollout with Audit Mode

Deploy new policies safely by starting in `audit` mode. Violations are logged but don't block traffic:

```yaml
  - name: new_content_policy_v2
    kind: experimental.ContentPolicyV2
    mode: audit          # observe only — no blocking, no modifications
    priority: 15
    hooks: [tool_pre_invoke]
```

Monitor your logs for violations. When you're confident the policy is tuned correctly, promote to `sequential`:

```yaml
    mode: sequential     # now enforcing
```

This gives you zero-risk rollout for any new policy.

---

## Input/Output Guardrails

Apply the same `transform` plugin to both pre- and post-invoke hooks to sanitize inputs and outputs:

```python
import re

from cpex.framework import Plugin, PluginConfig, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult, ToolPostInvokePayload, ToolPostInvokeResult

CREDIT_CARD = re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")


class PIIGuardrailPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if not payload.args:
            return ToolPreInvokeResult(continue_processing=True)
        cleaned = {
            k: CREDIT_CARD.sub("[CARD-REDACTED]", v) if isinstance(v, str) else v
            for k, v in payload.args.items()
        }
        return ToolPreInvokeResult(
            continue_processing=True,
            modified_payload=payload.model_copy(update={"args": cleaned}),
        )

    async def tool_post_invoke(
        self, payload: ToolPostInvokePayload, context: PluginContext
    ) -> ToolPostInvokeResult:
        if isinstance(payload.result, str):
            cleaned = CREDIT_CARD.sub("[CARD-REDACTED]", payload.result)
            return ToolPostInvokeResult(
                continue_processing=True,
                modified_payload=payload.model_copy(update={"result": cleaned}),
            )
        return ToolPostInvokeResult(continue_processing=True)
```

Configure with `mode: transform` so the plugin can modify payloads but never accidentally block the pipeline.

---

## Cross-Hook State

Use `PluginContext.state` to pass data between hooks within the same request lifecycle. The context persists across pre- and post-invoke hooks for the same request:

```python
import time

from cpex.framework import Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult, ToolPostInvokePayload, ToolPostInvokeResult


class LatencyTrackerPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        context.set_state("start_time", time.monotonic())
        return ToolPreInvokeResult(continue_processing=True)

    async def tool_post_invoke(
        self, payload: ToolPostInvokePayload, context: PluginContext
    ) -> ToolPostInvokeResult:
        start = context.get_state("start_time")
        if start:
            elapsed_ms = (time.monotonic() - start) * 1000
            context.set_state("tool_latency_ms", elapsed_ms)
        return ToolPostInvokeResult(continue_processing=True)
```

---

## Config-Driven Deny/Allow Lists

Drive plugin behavior from YAML config — no code changes needed to update the rules:

```python
from cpex.framework import Plugin, PluginConfig, PluginContext, PluginViolation, ToolPreInvokePayload, ToolPreInvokeResult


class ToolAllowListPlugin(Plugin):
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self._allowed = set((config.config or {}).get("allowed_tools", []))

    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if self._allowed and payload.name not in self._allowed:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason=f"Tool '{payload.name}' not in allow list",
                    description="Only explicitly allowed tools may be invoked.",
                    code="TOOL_NOT_ALLOWED",
                ),
            )
        return ToolPreInvokeResult(continue_processing=True)
```

```yaml
  - name: tool_allowlist
    kind: security.ToolAllowListPlugin
    mode: sequential
    priority: 5
    hooks: [tool_pre_invoke]
    config:
      allowed_tools:
        - web_search
        - calculator
        - file_read
```

---

## Plugin-Specific Config with Pydantic

Validate your plugin's `config` dict at init time using a Pydantic model. This gives you type safety, default values, and clear error messages:

```python
from pydantic import BaseModel
from cpex.framework import Plugin, PluginConfig


class RateLimitConfig(BaseModel):
    requests_per_minute: int = 60
    burst_size: int = 10
    scope: str = "user"  # "user" or "global"


class RateLimitPlugin(Plugin):
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self._settings = RateLimitConfig.model_validate(config.config or {})
```

If the YAML provides an invalid value (e.g., `requests_per_minute: "not_a_number"`), Pydantic raises a validation error at plugin initialization rather than at runtime.

---

## Idempotent Initialize and Shutdown

Make `initialize()` and `shutdown()` safe to call multiple times:

```python
class MyPlugin(Plugin):
    def __init__(self, config):
        super().__init__(config)
        self._client = None

    async def initialize(self):
        if self._client is None:
            self._client = await create_client()

    async def shutdown(self):
        if self._client is not None:
            await self._client.close()
            self._client = None
```

The plugin manager may call these methods more than once during lifecycle transitions. Guard against double-initialization and double-cleanup.

---

## Observability Stack

Use `fire_and_forget` plugins for telemetry that must never slow the pipeline:

```yaml
plugins:
  - name: request_tracer
    kind: observability.RequestTracerPlugin
    mode: fire_and_forget
    priority: 100
    hooks: [tool_pre_invoke, tool_post_invoke, prompt_pre_fetch, prompt_post_fetch]

  - name: metrics_collector
    kind: observability.MetricsPlugin
    mode: fire_and_forget
    priority: 101
    hooks: [tool_pre_invoke, tool_post_invoke]
```

These plugins receive an isolated snapshot of the payload, run asynchronously in the background, and their exceptions are logged but never propagated. The main pipeline is unaffected even if a telemetry backend is down.
