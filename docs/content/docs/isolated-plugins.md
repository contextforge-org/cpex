---
title: "Isolated Plugins"
weight: 80
---

# Isolated Plugins (venv)

Isolated plugins run in a separate Python virtual environment, preventing their dependencies from interfering with the host application. Each plugin gets its own venv with its own `requirements.txt`, while still communicating with the plugin manager through the standard hook interface.

---

## When to Use

- **Conflicting dependencies** — a plugin needs a different version of a library than your application
- **Untrusted code** — run third-party plugins in a sandboxed environment
- **Dependency hygiene** — keep the host environment clean from plugin-specific packages

---

## Configuration

Set `kind` to `"isolated_venv"` and provide the plugin details in the `config` section:

```yaml
plugins:
  - name: pii_scanner
    kind: isolated_venv
    version: "1.0.0"
    hooks:
      - tool_pre_invoke
      - tool_post_invoke
    mode: transform
    priority: 20
    config:
      class_name: pii_scanner.plugin.PIIScannerPlugin
      requirements_file: requirements.txt
      script_path: plugins/pii_scanner
```

### Config Fields

| Field | Description |
|-------|-------------|
| `class_name` | Fully qualified plugin class within the plugin directory (e.g., `pii_scanner.plugin.PIIScannerPlugin`) |
| `requirements_file` | Path to `requirements.txt` for the plugin's venv (relative to `script_path`) |
| `script_path` | Directory hosting the plugin, relative to the project root |

---

## Directory Structure

A typical isolated plugin layout:

```
plugins/
└── pii_scanner/
    ├── requirements.txt      # plugin-specific dependencies
    └── pii_scanner/
        ├── __init__.py
        └── plugin.py         # your Plugin subclass
```

The plugin class is written exactly like a native plugin:

```python
import re

from cpex.framework import Plugin, PluginContext, ToolPreInvokePayload, ToolPreInvokeResult

SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


class PIIScannerPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        if not payload.args:
            return ToolPreInvokeResult(continue_processing=True)

        cleaned = {
            k: SSN_PATTERN.sub("[REDACTED]", v) if isinstance(v, str) else v
            for k, v in payload.args.items()
        }
        return ToolPreInvokeResult(
            continue_processing=True,
            modified_payload=payload.model_copy(update={"args": cleaned}),
        )
```

---

## How It Works

1. **Venv creation** — CPEX creates a separate virtual environment for the plugin
2. **Dependency install** — packages from `requirements_file` are installed into the plugin's venv
3. **Worker process** — a subprocess is spawned running in the plugin's venv
4. **Communication** — payloads are serialized across the process boundary and deserialized on the other side
5. **Execution** — the plugin runs in its isolated process and returns results back to the manager

The process boundary means the plugin has full access to its own dependency tree without polluting or conflicting with the host environment.

---

## Trade-offs

| | Native Plugin | Isolated Plugin | External Plugin |
|--|:--:|:--:|:--:|
| Dependency isolation | No | Yes (venv) | Yes (process/container) |
| Startup overhead | None | Venv creation | Network connection |
| Latency per call | Minimal | Serialization cost | Network + serialization |
| Language support | Python only | Python only | Any (via protocol) |
| Scaling | In-process | In-process | Independent |

Use **native** when you control the dependencies. Use **isolated** when you need Python-level isolation without the operational complexity of running a separate service. Use **[external]({{< relref "/docs/external-plugins" >}})** when you need full process isolation, independent scaling, or non-Python implementations.
