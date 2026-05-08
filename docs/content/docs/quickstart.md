---
title: "Quick Start"
weight: 20
---

# Your First Plugin in 5 Minutes

This guide walks you through installing CPEX, writing a plugin, configuring it, and running it.

## Install

```bash
pip install cpex
```

## What Are Plugins?

Plugins let you intercept and modify execution at well-defined points — without changing the targeted application code.

You define **hooks** in your application where you want extensibility. Plugins attach to those hooks and run automatically whenever they fire.

## 1. Write a Plugin

A plugin is a class that subclasses `Plugin` and implements one or more hook handlers. Here you will create a plugin that blocks specific tools by name.

Create a file `plugins/tool_blocker.py`:

```python
import logging

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

log = logging.getLogger(__name__)


class ToolBlockerPlugin(Plugin):
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self._blocked = set(config.config.get("blocked_tools", []))

    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if payload.name in self._blocked:
            log.warning("Blocked tool: %s", payload.name)
            return ToolPreInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason=f"Tool '{payload.name}' is not allowed",
                    description="This tool has been blocked by policy.",
                    code="TOOL_BLOCKED",
                ),
            )
        return ToolPreInvokeResult(continue_processing=True)
```

The method name `tool_pre_invoke` matches the hook name — CPEX discovers it automatically. No decorator needed.

## 2. Configure the Plugin

Create `plugins/config.yaml`:

```yaml
plugin_dirs:
  - ./plugins

plugins:
  - name: tool_blocker
    kind: plugins.tool_blocker.ToolBlockerPlugin
    version: "1.0.0"
    hooks:
      - tool_pre_invoke
    mode: sequential
    priority: 10
    config:
      blocked_tools:
        - dangerous_tool
        - admin_delete
```

Key fields:

- **`kind`** — fully qualified class path to your plugin
- **`hooks`** — which hook points this plugin handles
- **`mode`** — execution mode (`sequential` lets you block *and* modify)
- **`priority`** — lower numbers run first (10 runs before 100)
- **`config`** — plugin-specific settings passed to your constructor

## 3. Run the Pipeline

```python
import asyncio
from cpex.framework import (
    GlobalContext,
    PluginManager,
    ToolPreInvokePayload,
)


async def main():
    manager = PluginManager("plugins/config.yaml")
    await manager.initialize()

    payload = ToolPreInvokePayload(name="dangerous_tool", args={"target": "production"})
    context = GlobalContext(request_id="req-001", user="alice")

    result, _ = await manager.invoke_hook("tool_pre_invoke", payload, context)

    if result.continue_processing:
        print("Allowed — proceed with tool call")
    else:
        print(f"Blocked: {result.violation.reason}")
        # Output: Blocked: Tool 'dangerous_tool' is not allowed

    await manager.shutdown()


asyncio.run(main())
```

That's it. Three files — a plugin, a config, and a driver — and you have a working enforcement pipeline.

---

## Alternative: The `@hook` Decorator

If you want the method name to differ from the hook name, use the `@hook` decorator:

```python
from cpex.framework import hook, Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult


class ToolBlockerPlugin(Plugin):
    @hook("tool_pre_invoke")
    async def check_tool_access(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        # same logic as before
        return ToolPreInvokeResult(continue_processing=True)
```

The decorator is also useful when a single plugin handles multiple hooks — you can give each method a descriptive name without worrying about naming collisions.

---

## Using `get_plugin_manager`

For applications that configure CPEX through environment variables (`PLUGINS_ENABLED=true`, `PLUGINS_CONFIG_FILE=plugins/config.yaml`), you can use the singleton helper instead of constructing the manager directly:

```python
from cpex.framework import get_plugin_manager

manager = get_plugin_manager()
if manager:
    await manager.initialize()
```

## Next Steps

Now that you have a working plugin, learn how hooks work in detail: [Hooks]({{< relref "/docs/hooks" >}}).
