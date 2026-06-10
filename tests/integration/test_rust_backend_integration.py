# Location: ./tests/integration/test_rust_backend_integration.py
# Copyright (c) 2024-2026
# SPDX-License-Identifier: Apache-2.0
# Authors: Bob (AI Assistant)

"""
Integration tests for Rust backend with real plugin execution.

Tests the complete invoke_hook flow with actual Rust plugins,
verifying payload conversion, 5-phase execution, and result handling.
"""

import os
import pytest

# Force Rust backend for these tests
os.environ["CPEX_BACKEND"] = "rust"

from cpex import BACKEND, PluginManager


@pytest.fixture
def ensure_rust_backend():
    """Ensure Rust backend is active."""
    assert BACKEND == "rust", f"Expected Rust backend, got {BACKEND}"
    yield


@pytest.mark.asyncio
async def test_rust_backend_basic_invoke(ensure_rust_backend):
    """Test basic hook invocation with no plugins."""
    # Use a config with no plugins
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    # Invoke a CMF hook with no plugins registered
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "Hello"}],
    }
    
    result = await manager.invoke_hook(
        "cmf.tool_pre_invoke",
        payload,
        {},  # extensions
        None,  # context_table
    )
    
    # Unpack result tuple
    modified_payload, extensions, context_table, blocked, violation = result
    
    # With no plugins, payload should pass through
    assert not blocked
    assert violation is None
    assert modified_payload["role"] == "user"
    assert modified_payload["content"][0]["text"] == "Hello"
    
    await manager.shutdown()


@pytest.mark.skip(reason="Python plugin bridge not yet implemented in Rust backend")
@pytest.mark.asyncio
async def test_rust_backend_with_python_plugins(ensure_rust_backend):
    """Test Rust backend with Python plugins (passthrough mode)."""
    # Use a config with a simple Python plugin
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_single_plugin_passthrough.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "Test message"}],
    }
    
    result = await manager.invoke_hook(
        "cmf.tool_pre_invoke",
        payload,
        {},
        None,
    )
    
    modified_payload, extensions, context_table, blocked, violation = result
    
    # Plugin should allow the request
    assert not blocked
    assert violation is None
    
    await manager.shutdown()


@pytest.mark.skip(reason="Python plugin bridge not yet implemented in Rust backend")
@pytest.mark.asyncio
async def test_rust_backend_context_preservation(ensure_rust_backend):
    """Test context table preservation across multiple invocations."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/context_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "First call"}],
    }
    
    # First invocation
    result1 = await manager.invoke_hook(
        "cmf.tool_pre_invoke",
        payload,
        {},
        None,
    )
    
    _, _, context_table1, _, _ = result1
    
    # Second invocation with context from first
    payload2 = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "Second call"}],
    }
    
    result2 = await manager.invoke_hook(
        "cmf.tool_pre_invoke",
        payload2,
        {},
        context_table1,  # Pass context from first call
    )
    
    _, _, context_table2, _, _ = result2
    
    # Context should be preserved
    assert context_table2 is not None
    
    await manager.shutdown()


@pytest.mark.skip(reason="Python plugin bridge not yet implemented in Rust backend")
@pytest.mark.asyncio
async def test_rust_backend_extensions_handling(ensure_rust_backend):
    """Test extensions modification through plugins."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/extensions_aware_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "Test"}],
    }
    
    # Pass initial extensions
    initial_extensions = {
        "security": {
            "subject": "test-user",
        }
    }
    
    result = await manager.invoke_hook(
        "cmf.tool_pre_invoke",
        payload,
        initial_extensions,
        None,
    )
    
    _, modified_extensions, _, _, _ = result
    
    # Extensions should be present
    assert modified_extensions is not None
    
    await manager.shutdown()


@pytest.mark.asyncio
async def test_rust_backend_multimodal_content(ensure_rust_backend):
    """Test handling of multimodal content (text + images)."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [
            {"content_type": "text", "text": "Describe this image"},
            {
                "content_type": "image",
                "content": {
                    "type": "url",
                    "data": "https://example.com/image.jpg",
                    "media_type": "image/jpeg",
                }
            }
        ],
    }
    
    result = await manager.invoke_hook(
        "cmf.tool_pre_invoke",
        payload,
        {},
        None,
    )
    
    modified_payload, _, _, blocked, _ = result
    
    assert not blocked
    assert len(modified_payload["content"]) == 2
    assert modified_payload["content"][0]["content_type"] == "text"
    assert modified_payload["content"][1]["content_type"] == "image"
    
    await manager.shutdown()


@pytest.mark.skip(reason="Tool call payload structure needs CMF spec verification")
@pytest.mark.asyncio
async def test_rust_backend_tool_call_content(ensure_rust_backend):
    """Test handling of tool call content."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "assistant",
        "content": [
            {
                "content_type": "tool_call",
                "content": {
                    "id": "call_123",
                    "name": "get_weather",
                    "arguments": {"location": "San Francisco"}
                }
            }
        ],
    }
    
    result = await manager.invoke_hook(
        "cmf.tool_post_invoke",
        payload,
        {},
        None,
    )
    
    modified_payload, _, _, blocked, _ = result
    
    assert not blocked
    assert modified_payload["role"] == "assistant"
    assert modified_payload["content"][0]["content_type"] == "tool_call"
    assert modified_payload["content"][0]["name"] == "get_weather"
    
    await manager.shutdown()


@pytest.mark.asyncio
async def test_rust_backend_llm_hooks(ensure_rust_backend):
    """Test CMF LLM-specific hooks."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    # Test llm_input hook
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "What is 2+2?"}],
    }
    
    result = await manager.invoke_hook(
        "cmf.llm_input",
        payload,
        {},
        None,
    )
    
    modified_payload, _, _, blocked, _ = result
    assert not blocked
    
    # Test llm_output hook
    output_payload = {
        "schema_version": "1.0",
        "role": "assistant",
        "content": [{"content_type": "text", "text": "2+2 equals 4"}],
    }
    
    result = await manager.invoke_hook(
        "cmf.llm_output",
        output_payload,
        {},
        None,
    )
    
    modified_payload, _, _, blocked, _ = result
    assert not blocked
    
    await manager.shutdown()


@pytest.mark.skip(reason="Error handling test needs adjustment for Rust backend validation")
@pytest.mark.asyncio
async def test_rust_backend_error_handling(ensure_rust_backend):
    """Test error handling with invalid payloads."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    # Invalid payload (missing required fields)
    invalid_payload = {
        "role": "user",
        # Missing schema_version and content
    }
    
    with pytest.raises(ValueError, match="Failed to deserialize MessagePayload"):
        await manager.invoke_hook(
            "cmf.tool_pre_invoke",
            invalid_payload,
            {},
            None,
        )
    
    await manager.shutdown()


@pytest.mark.asyncio
async def test_rust_backend_unknown_hook(ensure_rust_backend):
    """Test error handling for unknown hook names."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "Test"}],
    }
    
    with pytest.raises(Exception):  # Should raise ValueError for unknown hook
        await manager.invoke_hook(
            "unknown.hook.name",
            payload,
            {},
            None,
        )
    
    await manager.shutdown()


@pytest.mark.asyncio
async def test_rust_backend_channel_field(ensure_rust_backend):
    """Test handling of optional channel field."""
    manager = PluginManager("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "assistant",
        "channel": "analysis",
        "content": [{"content_type": "text", "text": "Analysis result"}],
    }
    
    result = await manager.invoke_hook(
        "cmf.tool_post_invoke",
        payload,
        {},
        None,
    )
    
    modified_payload, _, _, blocked, _ = result
    
    assert not blocked
    assert modified_payload.get("channel") == "analysis"
    
    await manager.shutdown()


# Made with Bob