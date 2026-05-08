---
title: "External Plugins"
weight: 70
---

# External Plugins

External plugins run as standalone services — separate processes, containers, or remote hosts — connected to CPEX over MCP (Streamable HTTP), gRPC, or Unix domain sockets. You write the same `Plugin` subclass, but it runs in its own server process.

---

## Why External Plugins?

- **Isolation** — plugin failures don't crash the host application
- **Independent scaling** — scale plugin servers separately from your gateway
- **Language independence** — implement the protocol in any language (the wire format is JSON/protobuf)
- **Security boundaries** — run untrusted plugins in sandboxed environments

---

## Building an External Plugin Server

Create your plugin class exactly as you would for a native plugin, then wrap it in `ExternalPluginServer`:

```python
import logging

from cpex.framework import (
    ExternalPluginServer,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

log = logging.getLogger(__name__)


class ArgumentValidatorPlugin(Plugin):
    async def tool_pre_invoke(
        self, payload: ToolPreInvokePayload, context: PluginContext
    ) -> ToolPreInvokeResult:
        max_len = (self.config.config or {}).get("max_arg_length", 10000)
        for key, value in (payload.args or {}).items():
            if isinstance(value, str) and len(value) > max_len:
                return ToolPreInvokeResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason=f"Argument '{key}' exceeds max length",
                        description=f"Argument is {len(value)} chars, limit is {max_len}.",
                        code="ARG_TOO_LONG",
                    ),
                )
        return ToolPreInvokeResult(continue_processing=True)


config = PluginConfig(
    name="argument_validator",
    kind="argument_validator.ArgumentValidatorPlugin",
    version="1.0.0",
    hooks=["tool_pre_invoke"],
    config={"max_arg_length": 5000},
)

server = ExternalPluginServer(plugins=[ArgumentValidatorPlugin(config)])
server.run()
```

Run this as a standalone process. It starts an MCP-compatible HTTP server.

---

## Transport Options

### MCP (Streamable HTTP)

The primary transport. The plugin runs as an MCP server over HTTP.

```yaml
plugins:
  - name: argument_validator
    kind: external
    hooks:
      - tool_pre_invoke
    mode: sequential
    priority: 10
    mcp:
      proto: STREAMABLEHTTP
      url: https://plugin-server.example.com
```

### gRPC

High-performance binary protocol with protobuf serialization.

```yaml
plugins:
  - name: argument_validator
    kind: external
    hooks:
      - tool_pre_invoke
    mode: sequential
    grpc:
      target: plugin-server.example.com:50051
```

Or over a Unix domain socket:

```yaml
    grpc:
      uds: /var/run/plugins/validator.sock
```

### Unix Domain Sockets

Low-latency local communication without network overhead. Uses a simple JSON-over-socket protocol.

```yaml
plugins:
  - name: argument_validator
    kind: external
    hooks:
      - tool_pre_invoke
    mode: sequential
    unix_socket:
      path: /var/run/plugins/validator.sock
```

---

## TLS / mTLS

For MCP and gRPC transports, you can configure TLS for encrypted communication and mTLS for mutual authentication.

### Client-side (gateway connecting to plugin)

```yaml
plugins:
  - name: secure_validator
    kind: external
    hooks:
      - tool_pre_invoke
    mcp:
      proto: STREAMABLEHTTP
      url: https://plugin-server.example.com
      tls:
        certfile: /path/to/client-cert.pem
        keyfile: /path/to/client-key.pem
        ca_bundle: /path/to/ca-bundle.pem
```

### Server-side (plugin accepting connections)

Configure via environment variables or `MCPServerConfig`:

```python
from cpex.framework.models import MCPServerConfig, MCPServerTLSConfig

server_config = MCPServerConfig(
    host="0.0.0.0",
    port=8443,
    tls=MCPServerTLSConfig(
        certfile="/path/to/server-cert.pem",
        keyfile="/path/to/server-key.pem",
        ca_bundle="/path/to/ca-bundle.pem",
    ),
)
```

---

## Key Constraints

- External plugins must set `kind: external` in the gateway config
- External plugins must have exactly **one** transport configured (`mcp`, `grpc`, or `unix_socket`)
- The `config` section **cannot** be set on the gateway side for external plugins — configuration is managed on the plugin server side
- The gateway fetches the plugin's manifest (hooks, config) from the remote server during `initialize()`

---

## Lifecycle

1. **Gateway starts** — `PluginManager.initialize()` connects to each external plugin server
2. **Manifest exchange** — the gateway fetches the plugin's available hooks and default config
3. **Hook execution** — payloads are serialized, sent to the remote plugin, and results deserialized
4. **Shutdown** — `PluginManager.shutdown()` closes all transport connections
