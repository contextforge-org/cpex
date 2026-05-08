---
title: "Configuration"
weight: 90
---

# Configuration Reference

Plugins are configured in a YAML file. You pass the file path when creating the `PluginManager`:

```python
manager = PluginManager("plugins/config.yaml")
```

Or set it via environment variable:

```bash
export PLUGINS_CONFIG_FILE=plugins/config.yaml
export PLUGINS_ENABLED=true
```

---

## YAML Structure

```yaml
plugin_dirs:
  - ./plugins

plugins:
  - name: content_filter
    kind: my_app.plugins.ContentFilterPlugin
    version: "1.0.0"
    description: "Blocks prohibited content in tool arguments"
    author: "platform-team"
    hooks:
      - tool_pre_invoke
    tags:
      - security
      - content
    mode: sequential
    on_error: fail
    priority: 10
    conditions:
      - server_ids: [prod-gateway]
        tenant_ids: [tenant-a, tenant-b]
    config:
      blocked_patterns:
        - "DROP TABLE"
        - "rm -rf"
```

---

## Plugin Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | *required* | Unique plugin identifier |
| `kind` | `str` | *required* | Fully qualified class path (e.g., `my_app.plugins.MyPlugin`), `"external"` for remote plugins, or `"isolated_venv"` for venv-isolated plugins |
| `version` | `str` | — | Semantic version |
| `description` | `str` | — | Human-readable description |
| `author` | `str` | — | Plugin author |
| `hooks` | `list[str]` | `[]` | Hook types this plugin handles |
| `tags` | `list[str]` | `[]` | Searchable tags |
| `mode` | `str` | `sequential` | Execution mode — see [Execution Modes]({{< relref "/docs/execution-modes" >}}) |
| `on_error` | `str` | `fail` | Error behavior: `fail`, `ignore`, `disable` |
| `priority` | `int` | `100` | Execution order within mode (lower = higher priority) |
| `conditions` | `list` | `[]` | When the plugin should execute |
| `capabilities` | `list[str]` | `[]` | Declared capabilities for [extension access]({{< relref "/docs/extensions" >}}) |
| `config` | `dict` | — | Plugin-specific settings passed to the constructor |
| `max_content_size` | `int` | `10000000` | Maximum payload size in bytes |
| `mcp` | `object` | — | MCP client config (for [external plugins]({{< relref "/docs/external-plugins" >}})) |
| `grpc` | `object` | — | gRPC client config (for external plugins) |
| `unix_socket` | `object` | — | Unix socket client config (for external plugins) |

---

## Plugin Directories

`plugin_dirs` lists directories that CPEX adds to the Python path for plugin discovery. Use this when your plugin classes live outside the main application package:

```yaml
plugin_dirs:
  - ./plugins
  - ./vendor/plugins
```

---

## Conditions

Conditions restrict when a plugin executes. If conditions are set and none match, the plugin is skipped for that invocation.

```yaml
conditions:
  - server_ids: [prod-gateway, staging-gateway]
    tenant_ids: [tenant-a]
  - tools: [web_search, code_exec]
```

Available condition fields:

| Field | Type | Description |
|-------|------|-------------|
| `server_ids` | `set[str]` | Match specific server IDs |
| `tenant_ids` | `set[str]` | Match specific tenant IDs |
| `tools` | `set[str]` | Match specific tool names |
| `prompts` | `set[str]` | Match specific prompt names |
| `resources` | `set[str]` | Match specific resource URIs |
| `agents` | `set[str]` | Match specific agent IDs |
| `user_patterns` | `list[str]` | Match user patterns |
| `content_types` | `list[str]` | Match content types |

Multiple conditions are OR'd — the plugin runs if **any** condition matches. Fields within a single condition are AND'd.

---

## Plugin-Specific Config

The `config` dict is passed to your plugin's constructor via `PluginConfig.config`. You access it in `__init__`:

```python
from pydantic import BaseModel
from cpex.framework import Plugin, PluginConfig


class FilterConfig(BaseModel):
    blocked_patterns: list[str]
    case_sensitive: bool = False


class ContentFilterPlugin(Plugin):
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self._filter = FilterConfig.model_validate(config.config)
```

Validating with a Pydantic model gives you type safety and clear error messages if the YAML config is malformed.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PLUGINS_ENABLED` | `false` | Enable the plugin framework |
| `PLUGINS_CONFIG_FILE` | `plugins/config.yaml` | Path to plugin configuration |
| `PLUGINS_PLUGIN_TIMEOUT` | `30` | Max execution time per plugin (seconds) |
| `PLUGINS_EXECUTION_POOL` | — | Max concurrent tasks (semaphore limit) |
| `PLUGINS_DEFAULT_HOOK_POLICY` | `allow` | Default policy for hooks without explicit rules: `allow` or `deny` |

---

## Legacy Mode Migration

If you are upgrading from an older version of CPEX, these mode names are automatically migrated:

| Legacy Mode | Current Equivalent |
|-------------|-------------------|
| `enforce` | `sequential` |
| `permissive` | `transform` |
| `enforce_ignore_error` | `sequential` + `on_error: ignore` |

---

## Complete Example

```yaml
plugin_dirs:
  - ./plugins

plugins:
  # Policy enforcement — blocks dangerous tools
  - name: tool_policy
    kind: plugins.security.ToolPolicyPlugin
    version: "1.0.0"
    hooks:
      - tool_pre_invoke
    mode: sequential
    priority: 10
    on_error: fail
    conditions:
      - server_ids: [prod-gateway]
    config:
      blocked_tools:
        - admin_delete
        - raw_sql_exec

  # PII redaction — cleans arguments before tools run
  - name: pii_redactor
    kind: plugins.privacy.PIIRedactionPlugin
    version: "1.0.0"
    hooks:
      - tool_pre_invoke
      - tool_post_invoke
    mode: transform
    priority: 20
    on_error: ignore

  # Audit logging — async, never blocks
  - name: audit_logger
    kind: plugins.observability.AuditLogPlugin
    version: "1.0.0"
    hooks:
      - tool_pre_invoke
      - tool_post_invoke
      - prompt_pre_fetch
    mode: fire_and_forget
    priority: 100
    on_error: ignore

  # Experimental policy — dry-run only
  - name: new_content_policy
    kind: plugins.experimental.ContentPolicyV2
    version: "0.1.0"
    hooks:
      - tool_pre_invoke
    mode: audit
    priority: 15
```

This pipeline runs in order: `tool_policy` (sequential, blocks) → `pii_redactor` (transform, modifies) → `new_content_policy` (audit, observes) → `audit_logger` (fire_and_forget, logs in background).
