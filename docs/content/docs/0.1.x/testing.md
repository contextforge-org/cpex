---
title: "Testing Plugins"
weight: 120
---

# Testing Plugins

Plugins are plain async classes — you can test them directly without the full framework. For integration testing, use `PluginManager` with a test configuration.

---

## Unit Testing

Call hook methods directly with constructed payloads and contexts. No framework overhead needed.

```python
import pytest

from cpex.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
)


@pytest.mark.asyncio
async def test_tool_blocker_blocks_dangerous_tool():
    config = PluginConfig(
        name="test_blocker",
        kind="plugins.tool_blocker.ToolBlockerPlugin",
        version="1.0.0",
        hooks=["tool_pre_invoke"],
        config={"blocked_tools": ["dangerous_tool", "admin_delete"]},
    )

    # Import your plugin class
    from plugins.tool_blocker import ToolBlockerPlugin

    plugin = ToolBlockerPlugin(config)

    payload = ToolPreInvokePayload(name="dangerous_tool", args={"target": "prod"})
    context = PluginContext(global_context=GlobalContext(request_id="test-001"))

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "TOOL_BLOCKED"
```

### Testing Allowed Requests

```python
@pytest.mark.asyncio
async def test_tool_blocker_allows_safe_tool():
    config = PluginConfig(
        name="test_blocker",
        kind="plugins.tool_blocker.ToolBlockerPlugin",
        version="1.0.0",
        hooks=["tool_pre_invoke"],
        config={"blocked_tools": ["dangerous_tool"]},
    )

    from plugins.tool_blocker import ToolBlockerPlugin

    plugin = ToolBlockerPlugin(config)

    payload = ToolPreInvokePayload(name="web_search", args={"query": "CPEX docs"})
    context = PluginContext(global_context=GlobalContext(request_id="test-002"))

    result = await plugin.tool_pre_invoke(payload, context)

    assert result.continue_processing is True
    assert result.violation is None
```

### Testing Payload Modification

```python
@pytest.mark.asyncio
async def test_pii_redaction_removes_emails():
    config = PluginConfig(
        name="test_redactor",
        kind="plugins.pii.PIIRedactionPlugin",
        version="1.0.0",
        hooks=["tool_pre_invoke"],
    )

    from plugins.pii import PIIRedactionPlugin

    plugin = PIIRedactionPlugin(config)

    payload = ToolPreInvokePayload(
        name="send_email",
        args={"body": "Contact alice@example.com for details"},
    )
    context = PluginContext(global_context=GlobalContext(request_id="test-003"))

    result = await plugin.redact_pii(payload, context)

    assert result.continue_processing is True
    assert result.modified_payload is not None
    assert "alice@example.com" not in result.modified_payload.args["body"]
    assert "[REDACTED]" in result.modified_payload.args["body"]
```

---

## Integration Testing

Use `PluginManager` with a test configuration to verify the full pipeline — mode ordering, priority, chaining, and condition matching.

```python
import tempfile
from pathlib import Path

import pytest
import yaml

from cpex.framework import GlobalContext, PluginManager, ToolPreInvokePayload


@pytest.fixture
async def manager(tmp_path):
    config = {
        "plugin_dirs": ["./plugins"],
        "plugins": [
            {
                "name": "blocker",
                "kind": "plugins.tool_blocker.ToolBlockerPlugin",
                "version": "1.0.0",
                "hooks": ["tool_pre_invoke"],
                "mode": "sequential",
                "priority": 10,
                "config": {"blocked_tools": ["dangerous_tool"]},
            },
            {
                "name": "redactor",
                "kind": "plugins.pii.PIIRedactionPlugin",
                "version": "1.0.0",
                "hooks": ["tool_pre_invoke"],
                "mode": "transform",
                "priority": 20,
            },
        ],
    }

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.dump(config))

    mgr = PluginManager(str(config_path))
    await mgr.initialize()
    yield mgr
    await mgr.shutdown()
    PluginManager.reset()


@pytest.mark.asyncio
async def test_pipeline_blocks_before_transform(manager):
    payload = ToolPreInvokePayload(name="dangerous_tool", args={"data": "alice@example.com"})
    context = GlobalContext(request_id="test-pipeline")

    result, _ = await manager.invoke_hook("tool_pre_invoke", payload, context)

    # Sequential blocker runs first (priority 10) and halts the pipeline
    assert result.continue_processing is False
    assert result.violation.code == "TOOL_BLOCKED"


@pytest.mark.asyncio
async def test_pipeline_chains_transform(manager):
    payload = ToolPreInvokePayload(
        name="web_search",
        args={"query": "contact alice@example.com"},
    )
    context = GlobalContext(request_id="test-chain")

    result, _ = await manager.invoke_hook("tool_pre_invoke", payload, context)

    # Blocker allows (not in blocked list), redactor transforms
    assert result.continue_processing is True
    if result.modified_payload:
        assert "alice@example.com" not in result.modified_payload.args["query"]
```

---

## Important: Reset Between Tests

`PluginManager` uses a Borg singleton pattern — all instances share state. Always call `PluginManager.reset()` in your teardown to clear shared state between tests:

```python
@pytest.fixture(autouse=True)
def reset_manager():
    yield
    PluginManager.reset()
```

---

## Testing with `invoke_hook_for_plugin`

To test a specific plugin in isolation within the manager (bypassing priority ordering), use `invoke_hook_for_plugin`:

```python
@pytest.mark.asyncio
async def test_specific_plugin(manager):
    payload = ToolPreInvokePayload(name="calculator", args={"a": "5"})
    context = GlobalContext(request_id="test-specific")

    result = await manager.invoke_hook_for_plugin(
        name="redactor",
        hook_type="tool_pre_invoke",
        payload=payload,
        context=context,
    )

    assert result.continue_processing is True
```

---

## Pytest Configuration

All hook methods are async, so you need `pytest-asyncio`. Add to your `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
```

Or mark individual tests with `@pytest.mark.asyncio`.
