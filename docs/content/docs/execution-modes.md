---
title: "Execution Modes"
weight: 45
---

# Execution Modes

Every plugin has an execution **mode** that controls whether it can block the pipeline, modify payloads, and how it runs relative to other plugins. Modes are set in the plugin's [YAML configuration]({{< relref "/docs/configuration" >}}).

## Phase Order

At each hook invocation, plugins are grouped by mode and dispatched in strict phase order:

```
sequential → transform → audit → concurrent → fire_and_forget
```

Within each serial phase, plugins execute in **priority order** — lower numbers run first (e.g., priority `10` runs before `20`). The default priority is `100`.

---

## The Five Modes

### `sequential`

Serial, chained execution. The default mode.

- Can **block** the pipeline (halt processing)
- Can **modify** payloads (downstream plugins see your changes)
- Global state is **merged** back to the shared context

Each plugin receives the chained output of the previous one. Use `sequential` when you need full control — policy enforcement combined with transformation.

```python
from cpex.framework import Plugin, PluginContext, PluginViolation, ToolPreInvokePayload, ToolPreInvokeResult


class TokenBudgetPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        budget = context.global_context.state.get("token_budget", 1000)
        if budget <= 0:
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Token budget exhausted",
                    description="No remaining tokens for this session.",
                    code="BUDGET_EXCEEDED",
                ),
            )
        return ToolPreInvokeResult(continue_processing=True)
```

### `transform`

Serial, chained execution — but **cannot block**.

- Cannot block (blocking attempts are logged and **suppressed**)
- Can **modify** payloads (downstream plugins see your changes)
- Global state is **merged** back

Use `transform` for data transformation pipelines — PII redaction, prompt rewriting, injecting defaults — where you want to guarantee the pipeline continues regardless.

```python
import re

from cpex.framework import hook, Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class PIIRedactionPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def redact(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if not payload.args:
            return ToolPreInvokeResult(continue_processing=True)

        cleaned = {
            k: EMAIL_PATTERN.sub("[REDACTED]", v) if isinstance(v, str) else v
            for k, v in payload.args.items()
        }
        return ToolPreInvokeResult(
            continue_processing=True,
            modified_payload=payload.model_copy(update={"args": cleaned}),
        )
```

### `audit`

Serial, observe-only.

- Cannot block (violations are **logged** but not enforced)
- Cannot modify (payload changes are **discarded**)
- Global state is **not merged**

Use `audit` for shadow policies, dry-run evaluation of new rules, and monitoring. Deploy a new policy in `audit` mode first, monitor the logs, then promote to `sequential` when you're confident.

```python
import logging

from cpex.framework import Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult

log = logging.getLogger(__name__)


class PolicyCanaryPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if payload.name in ("risky_tool", "experimental_api"):
            log.warning("Canary: tool '%s' would be blocked under new policy", payload.name)
        return ToolPreInvokeResult(continue_processing=True)
```

### `concurrent`

Parallel execution with fail-fast.

- Can **block** (first blocking result halts the pipeline and cancels remaining tasks)
- Cannot modify (payload changes are **discarded** to avoid non-deterministic last-writer-wins races)
- Global state is **merged** back

Use `concurrent` for independent policy gates that can be evaluated in parallel — each check doesn't depend on the others.

### `fire_and_forget`

Background execution via `asyncio.create_task()`.

- Cannot block
- Cannot modify
- Receives an **isolated snapshot** of the payload (copy-on-write)
- Fires **after all other phases** complete
- Exceptions are logged and **swallowed** — never propagated

Use `fire_and_forget` for telemetry, async logging, and side effects that must not slow the pipeline.

```python
import logging

from cpex.framework import Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult

log = logging.getLogger(__name__)


class AuditLogPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        log.info(
            "audit: tool=%s user=%s request=%s",
            payload.name,
            context.global_context.user,
            context.global_context.request_id,
        )
        return ToolPreInvokeResult(continue_processing=True)
```

### `disabled`

Plugin is skipped entirely — not loaded, not executed.

---

## Comparison Table

| Mode | Serial / Parallel | Can Block | Can Modify | State Merged | Errors Propagated |
|------|:-:|:-:|:-:|:-:|:-:|
| `sequential` | Serial | Yes | Yes | Yes | Via `on_error` |
| `transform` | Serial | No (suppressed) | Yes | Yes | Via `on_error` |
| `audit` | Serial | No (logged) | No (discarded) | No | Via `on_error` |
| `concurrent` | Parallel | Yes (fail-fast) | No (discarded) | Yes | Via `on_error` |
| `fire_and_forget` | Background | No | No | No | Swallowed |

---

## Chaining

In `sequential` and `transform` modes, modifications compose through the chain. If Plugin A redacts an email address from `payload.args` and Plugin B injects a default value, Plugin B receives the already-redacted payload and the caller sees both changes applied.

---

## Error Handling (`on_error`)

Error handling is configured **independently** of mode via the `on_error` field:

| `on_error` | Behavior |
|-----------|---------|
| `fail` | Pipeline halts, error propagates as `PluginError` (default) |
| `ignore` | Error logged, pipeline continues |
| `disable` | Error logged, plugin auto-disabled for remaining requests, pipeline continues |

```yaml
plugins:
  - name: strict_policy
    kind: my_app.StrictPlugin
    mode: sequential
    on_error: fail        # default — halt on errors

  - name: best_effort_enrichment
    kind: my_app.EnrichPlugin
    mode: transform
    on_error: ignore      # log and continue

  - name: flaky_integration
    kind: my_app.ExternalCheck
    mode: concurrent
    on_error: disable     # auto-disable after first failure
```

---

## Concurrency Pool

The `PLUGINS_EXECUTION_POOL` environment variable limits the number of concurrent tasks via semaphores. This prevents resource exhaustion when many `concurrent` or `fire_and_forget` plugins run simultaneously. Independent semaphores are used for each mode so one cannot starve the other.

---

## Choosing a Mode

| I want to... | Use |
|------|-----|
| Enforce policy and transform data | `sequential` |
| Transform data without enforcement power | `transform` |
| Monitor without affecting the pipeline | `audit` |
| Run independent checks in parallel | `concurrent` |
| Log or send telemetry without slowing anything | `fire_and_forget` |
| Disable a plugin without removing it | `disabled` |
