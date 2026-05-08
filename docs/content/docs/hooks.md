---
title: "Hooks"
weight: 30
---

# Hooks

A **hook** is a named interception point in your application. You define hooks where you want plugins to run, then call them at those points. The plugin manager dispatches the payload to every registered plugin and returns the combined result.

## Anatomy of a Hook Handler

Every hook handler is an `async` method on a `Plugin` subclass. It receives a typed **payload** and a **context**, and returns a **result**.

```python
from cpex.framework import (
    Plugin,
    PluginContext,
    PluginResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)


class MyPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        return ToolPreInvokeResult(continue_processing=True)
```

The framework validates the signature at registration time. It checks that the method:

1. Is `async` (not a regular function)
2. Accepts exactly 2 parameters (`payload`, `context`) — or 3 if the plugin uses [Extensions]({{< relref "/docs/extensions" >}})

---

## Binding Methods to Hooks

You have two options for connecting a method to a hook.

### Convention-Based

Name the method after the hook. The framework discovers it automatically:

```python
class MyPlugin(Plugin):
    async def tool_pre_invoke(self, payload, context):
        ...
```

### Decorator-Based

Use `@hook()` to decouple the method name from the hook name:

```python
from cpex.framework import hook


class MyPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def check_tool_access(self, payload, context):
        ...
```

You can also register a single method for multiple hooks:

```python
from cpex.framework import hook


class MyPlugin(Plugin):
    @hook(["tool_pre_invoke", "tool_post_invoke"])
    async def audit_tool_call(self, payload, context):
        ...
```

---

## Frozen Payloads

All payloads inherit from `PluginPayload`, which is frozen — you cannot mutate attributes directly:

```python
payload.name = "new_name"  # raises ValidationError
```

Instead, use `model_copy(update={...})` to create a modified copy:

```python
modified = payload.model_copy(update={"name": "sanitized_name"})
```

Return the modified copy via `PluginResult.modified_payload`. The framework chains modifications through the pipeline — each plugin receives the output of the previous one (in `sequential` and `transform` modes).

---

## Blocking Execution

To halt the pipeline, return a result with `continue_processing=False` and a `PluginViolation`:

```python
from cpex.framework import PluginViolation, ToolPreInvokeResult


async def tool_pre_invoke(self, payload, context):
    if payload.name == "prohibited_tool":
        return ToolPreInvokeResult(
            continue_processing=False,
            violation=PluginViolation(
                reason="Tool is prohibited",
                description="This tool has been blocked by organizational policy.",
                code="TOOL_PROHIBITED",
            ),
        )
    return ToolPreInvokeResult(continue_processing=True)
```

When a plugin blocks, the manager skips remaining plugins (in the current phase), fires any `fire_and_forget` tasks, and returns the violation to the caller.

Whether a plugin *can* block depends on its [execution mode]({{< relref "/docs/execution-modes" >}}). `sequential` and `concurrent` plugins can block; `transform`, `audit`, and `fire_and_forget` plugins cannot.

---

## Modifying Payloads

To transform the payload for downstream plugins and the caller, use `model_copy` and return the result:

```python
import re

from cpex.framework import hook, Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult

SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


class PIIRedactionPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def redact_pii(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if not payload.args:
            return ToolPreInvokeResult(continue_processing=True)

        redacted_args = {}
        for key, value in payload.args.items():
            if isinstance(value, str):
                redacted_args[key] = SSN_PATTERN.sub("[REDACTED-SSN]", value)
            else:
                redacted_args[key] = value

        modified = payload.model_copy(update={"args": redacted_args})
        return ToolPreInvokeResult(continue_processing=True, modified_payload=modified)
```

The next plugin in the chain receives the redacted payload — not the original. The caller sees the final modified payload in `result.modified_payload`.

---

## Payload Policies

Each hook type can declare which payload fields plugins are allowed to modify. This is enforced by a `HookPayloadPolicy`:

```python
from cpex.framework.hooks.policies import HookPayloadPolicy

policy = HookPayloadPolicy(writable_fields=frozenset({"args"}))
```

With this policy, a plugin that tries to change `payload.name` has that change silently discarded. Only changes to `args` are accepted.

When no explicit policy exists for a hook type, the `DefaultHookPolicy` setting applies:

- **`allow`** (default) — all modifications accepted
- **`deny`** — all modifications rejected unless a policy explicitly permits them

Set the default via environment variable: `PLUGINS_DEFAULT_HOOK_POLICY=deny`.

---

## Custom Hooks

You can register your own hooks for any domain. Define payload and result types, then register them:

```python
from cpex.framework import PluginPayload, PluginResult
from cpex.framework.hooks.registry import get_hook_registry


class EmailPayload(PluginPayload):
    recipient: str
    subject: str
    body: str


EmailResult = PluginResult[EmailPayload]

registry = get_hook_registry()
registry.register_hook("email_pre_send", EmailPayload, EmailResult)
```

Plugins can then attach to `email_pre_send` exactly like any built-in hook — via convention naming or the `@hook` decorator.

You can also register custom hooks directly from the decorator:

```python
from cpex.framework import hook, Plugin


class EmailFilterPlugin(Plugin):
    @hook("email_pre_send", EmailPayload, EmailResult)
    async def filter_email(self, payload, context):
        ...
```

Call the hook from your application:

```python
result, _ = await manager.invoke_hook("email_pre_send", payload, context)
if not result.continue_processing:
    raise PolicyError(result.violation.reason)
```

---

## Next Steps

Now that you understand hooks, explore the [built-in hook types]({{< relref "/docs/hook-types" >}}) or learn how [execution modes]({{< relref "/docs/execution-modes" >}}) control plugin behavior.
