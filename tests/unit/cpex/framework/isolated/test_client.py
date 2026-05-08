# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_client.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Unit tests for IsolatedVenvPlugin.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cpex.framework.errors import PluginError
from cpex.framework.hooks.prompts import PromptPosthookResult, PromptPrehookResult
from cpex.framework.hooks.tools import ToolPostInvokeResult, ToolPreInvokeResult
from cpex.framework.isolated.client import IsolatedVenvPlugin
from cpex.framework.models import PluginConfig, PluginContext, PluginErrorModel


class TestIsolatedVenvPlugin:
    """Test suite for IsolatedVenvPlugin class."""

    @pytest.fixture
    def mock_config(self, tmp_path):
        """Create a mock plugin configuration."""
        # Create the test_plugin directory structure
        plugin_dir = tmp_path / "test_plugin"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        # Create requirements.txt file
        requirements_file = plugin_dir / "requirements.txt"
        requirements_file.write_text("pytest>=7.0.0\n")

        venv_path = tmp_path / ".venv"

        config_dict = {
            "name": "test_plugin",
            "kind": "isolated_venv",
            "description": "Test plugin",
            "version": "1.0.0",
            "author": "Test",
            "hooks": ["tool_pre_invoke"],
            "config": {
                "class_name": "test_plugin.TestPlugin",
                "venv_path": venv_path,
                "requirements_file": "requirements.txt",  # Use relative path
            },
        }

        return PluginConfig(**config_dict)

    @pytest.fixture
    def plugin(self, mock_config, tmp_path):
        """Create an IsolatedVenvPlugin instance."""
        plugin_instance = IsolatedVenvPlugin(mock_config, plugin_dirs=[tmp_path])
        # Override plugin_path to use tmp_path for testing
        plugin_instance.plugin_path = tmp_path / "test_plugin"
        return plugin_instance

    @pytest.fixture
    def plugin_context(self):
        """Create a PluginContext instance"""
        context = {"state": {}, "global_context": {"request_id": "req-123"}, "metadata": {}}
        plugin_context = PluginContext(
            state=context.get("state"), global_context=context.get("global_context"), metadata=context.get("metadata")
        )
        return plugin_context

    def test_init(self, plugin):
        """Test plugin initialization."""
        assert plugin.name == "test_plugin"
        assert plugin.implementation == "Python"
        assert plugin.comm is None

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.venv.EnvBuilder")
    async def test_create_venv_success(self, mock_builder_class, plugin, tmp_path):
        """Test successful venv creation."""
        venv_path = tmp_path / ".venv"
        mock_builder = MagicMock()
        mock_builder_class.return_value = mock_builder

        await plugin.create_venv(str(venv_path))

        mock_builder_class.assert_called_once()
        mock_builder.create.assert_called_once_with(str(venv_path))

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.venv.EnvBuilder")
    async def test_create_venv_failure(self, mock_builder_class, plugin, tmp_path):
        """Test venv creation failure."""
        venv_path = tmp_path / ".venv"
        mock_builder = MagicMock()
        mock_builder.create.side_effect = Exception("Creation failed")
        mock_builder_class.return_value = mock_builder

        with pytest.raises(Exception, match="Creation failed"):
            await plugin.create_venv(str(venv_path))

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_initialize_success(self, mock_create_venv, mock_comm_class, plugin):
        """Test successful plugin initialization."""
        mock_create_venv.return_value = True
        mock_comm = MagicMock()
        mock_comm_class.return_value = mock_comm

        await plugin.initialize()

        mock_create_venv.assert_called_once()
        mock_comm_class.assert_called_once()
        mock_comm.install_requirements.assert_called_once()
        assert plugin.comm is not None

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_unregistered_hook_type(self, mock_get_registry, plugin, plugin_context):
        """Test invoking an unregistered hook type."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = None
        mock_get_registry.return_value = mock_registry

        plugin.comm = MagicMock()

        with pytest.raises(PluginError, match="Hook type .* not registered"):
            await plugin.invoke_hook("invalid_hook", None, plugin_context)

    @pytest.mark.asyncio
    async def test_invoke_hook_no_comm(self, plugin, plugin_context):
        """Test invoking hook without initialized communicator."""
        plugin.comm = None
        with pytest.raises(PluginError, match="Plugin comm not initialized"):
            await plugin.invoke_hook("tool_pre_invoke", None, plugin_context)

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_tool_pre_invoke_success(self, mock_get_registry, plugin, plugin_context):
        """Test successful tool_pre_invoke hook invocation."""
        # Setup registry
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = ToolPreInvokeResult
        mock_get_registry.return_value = mock_registry
        response_data = {
            "continue_processing": True,
            "modified_payload": {"name": "test_tool", "args": {}},
            "violation": None,
            "metadata": {},
        }

        mock_registry.json_to_result = MagicMock()
        mock_registry.json_to_result.return_value = ToolPreInvokeResult(
            continue_processing=response_data.get("continue_processing"),
            modified_payload=response_data.get("modified_payload"),
            violation=response_data.get("violation"),
            metadata=response_data.get("metadata"),
        )
        # Setup communicator
        mock_comm = MagicMock()
        mock_comm.send_task.return_value = response_data
        plugin.comm = mock_comm

        # Create payload and context
        from cpex.framework.hooks.tools import ToolPreInvokePayload

        payload = ToolPreInvokePayload(name="test_tool", args={})
        result = await plugin.invoke_hook("tool_pre_invoke", payload, plugin_context)

        assert isinstance(result, ToolPreInvokeResult)
        assert result.continue_processing is True
        mock_comm.send_task.assert_called_once()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_tool_post_invoke_success(self, mock_get_registry, plugin, plugin_context):
        """Test successful tool_post_invoke hook invocation."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = ToolPostInvokeResult
        mock_get_registry.return_value = mock_registry

        mock_comm = MagicMock()
        response_data = {
            "continue_processing": True,
            "modified_payload": {"name": "test_tool", "result": "success"},
            "violation": None,
            "metadata": {},
        }
        mock_comm.send_task.return_value = response_data
        mock_registry.json_to_result = MagicMock()
        mock_registry.json_to_result.return_value = ToolPostInvokeResult(
            continue_processing=response_data.get("continue_processing"),
            modified_payload=response_data.get("modified_payload"),
            violation=response_data.get("violation"),
            metadata=response_data.get("metadata"),
        )
        plugin.comm = mock_comm

        from cpex.framework.hooks.tools import ToolPostInvokePayload

        payload = ToolPostInvokePayload(name="test_tool", result="success")

        result = await plugin.invoke_hook("tool_post_invoke", payload, plugin_context)

        assert isinstance(result, ToolPostInvokeResult)
        assert result.continue_processing is True

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_prompt_pre_fetch_success(self, mock_get_registry, plugin, plugin_context):
        """Test successful prompt_pre_fetch hook invocation."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = PromptPrehookResult
        mock_registry.json_to_result = MagicMock()
        mock_get_registry.return_value = mock_registry

        mock_comm = MagicMock()
        response_data = {
            "continue_processing": True,
            "modified_payload": {"prompt_id": "test", "args": {}},
            "violation": None,
            "metadata": {},
        }
        mock_comm.send_task.return_value = response_data
        mock_registry.json_to_result.return_value = PromptPrehookResult(
            continue_processing=response_data.get("continue_processing"),
            modified_payload=response_data.get("modified_payload"),
            violation=response_data.get("violation"),
            metadata=response_data.get("metadata"),
        )
        plugin.comm = mock_comm

        from cpex.framework.hooks.prompts import PromptPrehookPayload

        payload = PromptPrehookPayload(prompt_id="test", args={})

        result = await plugin.invoke_hook("prompt_pre_fetch", payload, plugin_context)

        assert isinstance(result, PromptPrehookResult)
        assert result.continue_processing is True

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_prompt_post_fetch_success(self, mock_get_registry, plugin, plugin_context):
        """Test successful prompt_post_fetch hook invocation."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = PromptPosthookResult
        mock_get_registry.return_value = mock_registry

        mock_comm = MagicMock()
        response_data = {
            "continue_processing": True,
            "modified_payload": {"prompt_id": "test", "result": {}},
            "violation": None,
            "metadata": {},
        }
        mock_registry.json_to_result = MagicMock()
        mock_registry.json_to_result.return_value = PromptPosthookResult(
            continue_processing=response_data.get("continue_processing"),
            modified_payload=response_data.get("modified_payload"),
            violation=response_data.get("violation"),
            metadata=response_data.get("metadata"),
        )
        mock_comm.send_task.return_value = response_data
        plugin.comm = mock_comm

        from cpex.framework.hooks.prompts import PromptPosthookPayload

        payload = PromptPosthookPayload(prompt_id="test", result={})
        result = await plugin.invoke_hook("prompt_post_fetch", payload, plugin_context)

        assert isinstance(result, PromptPosthookResult)
        assert result.continue_processing is True

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_with_violation(self, mock_get_registry, plugin, plugin_context):
        """Test hook invocation that returns a violation."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = ToolPreInvokeResult
        mock_get_registry.return_value = mock_registry
        mock_registry.json_to_result = MagicMock()

        mock_comm = MagicMock()
        response_data = {
            "continue_processing": False,
            "modified_payload": None,
            "violation": {"reason": "Policy violation", "description": "severity high", "code": "PROHIBITED_CONTENT"},
            "metadata": {},
        }
        mock_comm.send_task.return_value = response_data
        plugin.comm = mock_comm
        mock_registry.json_to_result.return_value = ToolPreInvokeResult(
            continue_processing=response_data.get("continue_processing"),
            modified_payload=response_data.get("modified_payload"),
            violation=response_data.get("violation"),
            metadata=response_data.get("metadata"),
        )

        from cpex.framework.hooks.tools import ToolPreInvokePayload

        payload = ToolPreInvokePayload(name="test_tool", args={})

        result = await plugin.invoke_hook("tool_pre_invoke", payload, plugin_context)

        assert isinstance(result, ToolPreInvokeResult)
        assert result.continue_processing is False
        assert result.violation is not None

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_plugin_error(self, mock_get_registry, plugin, plugin_context):
        """Test hook invocation that raises PluginError."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = ToolPreInvokeResult
        mock_get_registry.return_value = mock_registry

        mock_comm = MagicMock()
        mock_comm.send_task.side_effect = PluginError(
            error=PluginErrorModel(message="Test error", plugin_name="test_plugin")
        )
        plugin.comm = mock_comm

        from cpex.framework.hooks.tools import ToolPreInvokePayload

        payload = ToolPreInvokePayload(name="test_tool", args={})
        with pytest.raises(PluginError):
            await plugin.invoke_hook("tool_pre_invoke", payload, plugin_context)

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    @patch("cpex.framework.isolated.client.convert_exception_to_error")
    async def test_invoke_hook_generic_exception(self, mock_convert, mock_get_registry, plugin, plugin_context):
        """Test hook invocation that raises generic exception."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = ToolPreInvokeResult
        mock_get_registry.return_value = mock_registry

        mock_comm = MagicMock()
        mock_comm.send_task.side_effect = ValueError("Test error")
        plugin.comm = mock_comm

        mock_convert.return_value = PluginErrorModel(message="Converted error", plugin_name="test_plugin")

        from cpex.framework.hooks.tools import ToolPreInvokePayload

        payload = ToolPreInvokePayload(name="test_tool", args={})

        with pytest.raises(PluginError):
            await plugin.invoke_hook("tool_pre_invoke", payload, plugin_context)

        mock_convert.assert_called_once()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.get_hook_registry")
    async def test_invoke_hook_serialization(self, mock_get_registry, plugin):
        """Test that payload and context are properly serialized."""
        mock_registry = MagicMock()
        mock_registry.get_result_type.return_value = ToolPreInvokeResult
        mock_get_registry.return_value = mock_registry

        mock_comm = MagicMock()
        response_data = {"continue_processing": True, "modified_payload": None, "violation": None, "metadata": {}}
        mock_comm.send_task.return_value = response_data
        plugin.comm = mock_comm

        from cpex.framework import GlobalContext
        from cpex.framework.hooks.tools import ToolPreInvokePayload

        payload = ToolPreInvokePayload(name="test_tool", args={"key": "value"})
        global_ctx = GlobalContext(request_id="req-123", user="alice")
        context = PluginContext(global_context=global_ctx)

        await plugin.invoke_hook("tool_pre_invoke", payload, context)

        # Verify send_task was called with serialized data
        call_args = mock_comm.send_task.call_args
        task_data = call_args[1]["task_data"]

        assert "payload" in task_data
        assert "context" in task_data
        assert task_data["hook_type"] == "tool_pre_invoke"
        assert task_data["plugin_name"] == plugin.name

    def test_get_safe_config(self, plugin):
        """Test that get_safe_config returns sanitized config."""
        safe_config = plugin.config.get_safe_config()
        assert isinstance(safe_config, str)
        # Should be valid JSON
        import json

        config_dict = json.loads(safe_config)
        assert "name" in config_dict

    def test_cache_dir_creation(self, plugin):
        """Test that cache directory is created on plugin initialization."""
        assert plugin.cache_dir.exists()
        assert plugin.cache_dir.is_dir()
        assert plugin.cache_dir.name == "venv_cache"

    def test_compute_requirements_hash_with_file(self, plugin, tmp_path):
        """Test computing hash of existing requirements file."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\nrequests==2.28.0\n")

        hash1 = plugin._compute_requirements_hash(str(req_file))
        assert isinstance(hash1, str)
        assert len(hash1) == 64  # SHA256 produces 64 hex characters

        # Same content should produce same hash
        hash2 = plugin._compute_requirements_hash(str(req_file))
        assert hash1 == hash2

    def test_compute_requirements_hash_different_content(self, plugin, tmp_path):
        """Test that different content produces different hashes."""
        req_file1 = tmp_path / "requirements1.txt"
        req_file1.write_text("pytest==7.0.0\n")

        req_file2 = tmp_path / "requirements2.txt"
        req_file2.write_text("pytest==8.0.0\n")

        hash1 = plugin._compute_requirements_hash(str(req_file1))
        hash2 = plugin._compute_requirements_hash(str(req_file2))

        assert hash1 != hash2

    def test_compute_requirements_hash_nonexistent_file(self, plugin, tmp_path):
        """Test computing hash of non-existent file."""
        nonexistent = tmp_path / "nonexistent.txt"
        hash_result = plugin._compute_requirements_hash(str(nonexistent))

        # Should return hash of empty content
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64

    def test_get_cache_metadata_path(self, plugin, tmp_path):
        """Test getting cache metadata path."""
        venv_path = tmp_path / ".venv"
        metadata_path = plugin._get_cache_metadata_path(str(venv_path))

        assert metadata_path.parent == plugin.cache_dir
        assert metadata_path.name == ".venv_metadata.json"
        assert isinstance(metadata_path, Path)

    def test_is_venv_cache_valid_no_venv(self, plugin, tmp_path):
        """Test cache validation when venv doesn't exist."""
        venv_path = tmp_path / ".venv"
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        result = plugin._is_venv_cache_valid(str(venv_path), str(req_file))
        assert result is False

    def test_is_venv_cache_valid_no_metadata(self, plugin, tmp_path):
        """Test cache validation when metadata file doesn't exist."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        result = plugin._is_venv_cache_valid(str(venv_path), str(req_file))
        assert result is False

    def test_is_venv_cache_valid_hash_mismatch(self, plugin, tmp_path):
        """Test cache validation when requirements hash doesn't match."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        # Create metadata with different hash
        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        metadata = {
            "venv_path": str(venv_path),
            "requirements_file": str(req_file),
            "requirements_hash": "different_hash",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
        metadata_path.write_text(json.dumps(metadata))

        result = plugin._is_venv_cache_valid(str(venv_path), str(req_file))
        assert result is False

    def test_is_venv_cache_valid_success(self, plugin, tmp_path):
        """Test successful cache validation."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        # Create metadata with correct hash
        req_hash = plugin._compute_requirements_hash(str(req_file))
        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        metadata = {
            "venv_path": str(venv_path),
            "requirements_file": str(req_file),
            "requirements_hash": req_hash,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
        metadata_path.write_text(json.dumps(metadata))

        result = plugin._is_venv_cache_valid(str(venv_path), str(req_file))
        assert result is True

    def test_is_venv_cache_valid_invalid_json(self, plugin, tmp_path):
        """Test cache validation with invalid JSON metadata."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        # Create invalid JSON metadata
        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        metadata_path.write_text("invalid json {")

        result = plugin._is_venv_cache_valid(str(venv_path), str(req_file))
        assert result is False

    def test_save_cache_metadata(self, plugin, tmp_path):
        """Test saving cache metadata."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        plugin._save_cache_metadata(str(venv_path), str(req_file))

        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        assert metadata_path.exists()

        with open(metadata_path) as f:
            metadata = json.load(f)

        assert "venv_path" in metadata
        assert "requirements_file" in metadata
        assert "requirements_hash" in metadata
        assert "python_version" in metadata
        assert metadata["requirements_hash"] == plugin._compute_requirements_hash(str(req_file))

    def test_save_cache_metadata_nonexistent_requirements(self, plugin, tmp_path):
        """Test saving cache metadata with non-existent requirements file."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "nonexistent.txt"

        plugin._save_cache_metadata(str(venv_path), str(req_file))

        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        assert metadata_path.exists()

        with open(metadata_path) as f:
            metadata = json.load(f)

        assert metadata["requirements_file"] is None

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.venv.EnvBuilder")
    @patch("cpex.framework.isolated.client.shutil.rmtree")
    async def test_create_venv_with_cache_valid(self, mock_rmtree, mock_builder_class, plugin, tmp_path):
        """Test create_venv uses cache when valid."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        # Setup valid cache
        plugin._save_cache_metadata(str(venv_path), str(req_file))

        await plugin.create_venv(str(venv_path), str(req_file), use_cache=True)

        # Should not create new venv or remove existing
        mock_builder_class.assert_not_called()
        mock_rmtree.assert_not_called()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.venv.EnvBuilder")
    @patch("cpex.framework.isolated.client.shutil.rmtree")
    async def test_create_venv_with_cache_invalid(self, mock_rmtree, mock_builder_class, plugin, tmp_path):
        """Test create_venv recreates when cache invalid."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        # Setup invalid cache (wrong hash)
        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        metadata = {
            "venv_path": str(venv_path),
            "requirements_file": str(req_file),
            "requirements_hash": "wrong_hash",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
        metadata_path.write_text(json.dumps(metadata))

        mock_builder = MagicMock()
        mock_builder_class.return_value = mock_builder

        await plugin.create_venv(str(venv_path), str(req_file), use_cache=True)

        # Should remove old venv and create new one
        mock_rmtree.assert_called_once_with(venv_path)
        mock_builder_class.assert_called_once()
        mock_builder.create.assert_called_once()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.venv.EnvBuilder")
    async def test_create_venv_without_cache(self, mock_builder_class, plugin, tmp_path):
        """Test create_venv without using cache."""
        venv_path = tmp_path / ".venv"
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("pytest==7.0.0\n")

        mock_builder = MagicMock()
        mock_builder_class.return_value = mock_builder

        await plugin.create_venv(str(venv_path), str(req_file), use_cache=False)

        # Should create new venv
        mock_builder_class.assert_called_once()
        mock_builder.create.assert_called_once()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    @patch.object(IsolatedVenvPlugin, "_is_venv_cache_valid")
    async def test_initialize_with_valid_cache(self, mock_cache_valid, mock_create_venv, mock_comm_class, plugin):
        """Test initialize with valid cache skips requirements installation."""
        mock_cache_valid.return_value = True
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm_class.return_value = mock_comm

        await plugin.initialize()

        # Should not install requirements when cache is valid
        mock_comm.install_requirements.assert_not_called()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    @patch.object(IsolatedVenvPlugin, "_is_venv_cache_valid")
    @patch.object(IsolatedVenvPlugin, "_save_cache_metadata")
    async def test_initialize_with_invalid_cache(
        self, mock_save_metadata, mock_cache_valid, mock_create_venv, mock_comm_class, plugin
    ):
        """Test initialize with invalid cache installs requirements."""
        mock_cache_valid.return_value = False
        mock_create_venv.return_value = True
        mock_comm = MagicMock()
        mock_comm_class.return_value = mock_comm

        await plugin.initialize()

        # Should install requirements when cache is invalid
        mock_comm.install_requirements.assert_called_once()
        mock_save_metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup(self, plugin):
        """Test cleanup method stops worker process."""
        mock_comm = MagicMock()
        plugin.comm = mock_comm

        await plugin.cleanup()

        mock_comm.stop_worker.assert_called_once()
        assert plugin.comm is None

    @pytest.mark.asyncio
    async def test_cleanup_no_comm(self, plugin):
        """Test cleanup when comm is None."""
        plugin.comm = None

        # Should not raise error
        await plugin.cleanup()


# Made with Bob
