# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_integration.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Integration tests for isolated plugin system.
"""

from unittest.mock import MagicMock, patch

import pytest
import yaml

from cpex.framework import GlobalContext, PluginManager
from cpex.framework.hooks.tools import ToolPreInvokePayload
from cpex.framework.isolated.client import IsolatedVenvPlugin
from cpex.framework.models import Config, PluginConfig


class TestIsolatedPluginIntegration:
    """Integration tests for the isolated plugin system."""

    @pytest.fixture
    def integration_config_path(self, tmp_path):
        """Create a temporary config file for integration testing."""

        cfg = Config(
            plugins=[
                PluginConfig(
                    name="test_isolated_plugin",
                    kind="isolated_venv",
                    description="Test isolated plugin",
                    version="1.0.0",
                    author="Test",
                    hooks=["tool_pre_invoke"],
                    config={"class_name": "test_plugin.TestPlugin", "requirements_file": "requirements.txt"},
                )
            ],
            plugin_dirs=[str((tmp_path / "xplugins").resolve())],
            plugin_settings={
                "parallel_execution_within_band": True,
                "plugin_timeout": 30,
                "fail_on_plugin_error": False,
            },
        )
        config_file = tmp_path / "xplugins" / "test_config.yaml"
        class_root = tmp_path / "xplugins" / "test_plugin"
        class_root.mkdir(parents=True, exist_ok=True)
        dumped_cfg = cfg.model_dump(mode="json")
        config_content = yaml.safe_dump(dumped_cfg, default_flow_style=False)
        config_file.write_text(config_content)
        return str(config_file)

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_plugin_manager_with_isolated_plugin(
        self, mock_create_venv, mock_comm_class, integration_config_path, tmp_path
    ):
        """Test PluginManager loading and initializing an isolated plugin."""
        # Setup mocks
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm.install_requirements = MagicMock()
        mock_comm_class.return_value = mock_comm
        with patch("cpex.framework.loader.plugin.ALLOWED_PLUGIN_DIRS", {str((tmp_path / "xplugins").resolve())}):
            # Create manager
            manager = PluginManager(integration_config_path)

            await manager.initialize()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_isolated_plugin_full_lifecycle(self, mock_create_venv, mock_comm_class, tmp_path):
        """Test full lifecycle of an isolated plugin."""
        # Setup
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm.install_requirements = MagicMock()
        mock_comm.send_task.return_value = {
            "continue_processing": True,
            "modified_payload": None,
            "violation": None,
            "metadata": {},
        }
        mock_comm_class.return_value = mock_comm

        config_dict = {
            "name": "test_plugin",
            "kind": "isolated_venv",
            "description": "Test plugin",
            "version": "1.0.0",
            "author": "Test",
            "hooks": ["tool_pre_invoke"],
            "config": {
                "class_name": "test_plugin.TestPlugin",
                "requirements_file": "requirements.txt",
            },
        }
        resolved_plugin_path = (tmp_path / "xplugins").resolve()
        plugin_root = resolved_plugin_path / "test_plugin"
        plugin_root.mkdir(parents=True, exist_ok=True)
        # resolved_plugin_path.mkdir(parents=True, exist_ok=True)
        with patch("cpex.framework.loader.plugin.ALLOWED_PLUGIN_DIRS", {str(resolved_plugin_path)}):
            config = PluginConfig(**config_dict)

            # Create and initialize plugin
            plugin = IsolatedVenvPlugin(config, plugin_dirs=[resolved_plugin_path])

            with patch("cpex.framework.isolated.client.get_hook_registry") as mock_registry:
                from cpex.framework.hooks.tools import ToolPreInvokeResult

                mock_reg = MagicMock()
                mock_reg.get_result_type.return_value = ToolPreInvokeResult
                mock_reg.json_to_result = MagicMock()
                mock_reg.json_to_result.return_value = ToolPreInvokeResult(continue_processing=True)
                mock_registry.return_value = mock_reg

                await plugin.initialize()

                # Invoke hook
                payload = ToolPreInvokePayload(name="test_tool", args={})
                global_ctx = GlobalContext(request_id="req-123")
                from cpex.framework.models import PluginContext

                context = PluginContext(global_context=global_ctx)

                result = await plugin.invoke_hook("tool_pre_invoke", payload, context)

                assert result is not None
                assert result.continue_processing is True

    @pytest.mark.asyncio
    async def test_isolated_plugin_error_handling(self, tmp_path):
        """Test error handling in isolated plugin."""
        config_dict = {
            "name": "test_plugin",
            "kind": "isolated_venv",
            "description": "Test plugin",
            "version": "1.0.0",
            "author": "Test",
            "hooks": ["tool_pre_invoke"],
            "config": {
                "class_name": "test_plugin.TestPlugin",
                "requirements_file": "requirements.txt",
            },
        }
        config = PluginConfig(**config_dict)
        resolved_plugin_path = (tmp_path / "xplugins").resolve()
        cache_root = resolved_plugin_path / "test_plugin"
        cache_root.mkdir(parents=True, exist_ok=True)
        # resolved_plugin_path.mkdir(parents=True, exist_ok=True)

        plugin = IsolatedVenvPlugin(config, plugin_dirs=[str(resolved_plugin_path)])

        # Try to invoke hook without initialization
        from cpex.framework.errors import PluginError

        payload = ToolPreInvokePayload(name="test_tool", args={})
        global_ctx = GlobalContext(request_id="req-123")
        from cpex.framework.models import PluginContext

        context = PluginContext(global_context=global_ctx)

        with pytest.raises(PluginError, match="Plugin comm not initialized"):
            await plugin.invoke_hook("tool_pre_invoke", payload, context)

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_isolated_plugin_with_multiple_hooks(self, mock_create_venv, mock_comm_class, tmp_path):
        """Test isolated plugin with multiple hook types."""
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm.install_requirements = MagicMock()
        mock_comm_class.return_value = mock_comm

        config_dict = {
            "name": "test_plugin",
            "kind": "isolated_venv",
            "description": "Test plugin",
            "version": "1.0.0",
            "author": "Test",
            "hooks": ["tool_pre_invoke", "tool_post_invoke", "prompt_pre_fetch", "prompt_post_fetch"],
            "config": {
                "class_name": "test_plugin.TestPlugin",
                "requirements_file": "requirements.txt",
                "script_path": "tests/unit/cpex/fixtures/plugins/isolated",
            },
        }

        config = PluginConfig(**config_dict)
        resolved_plugin_path = (tmp_path / "xplugins").resolve()
        cache_root = resolved_plugin_path / "test_plugin"
        cache_root.mkdir(parents=True, exist_ok=True)

        plugin = IsolatedVenvPlugin(config, plugin_dirs=[str(resolved_plugin_path)])

        await plugin.initialize()

        # Test each hook type
        hook_types = [
            ("tool_pre_invoke", "ToolPreInvokeResult"),
            ("tool_post_invoke", "ToolPostInvokeResult"),
            ("prompt_pre_fetch", "PromptPrehookResult"),
            ("prompt_post_fetch", "PromptPosthookResult"),
        ]

        for hook_type, result_type_name in hook_types:
            mock_comm.send_task.return_value = {
                "continue_processing": True,
                "modified_payload": None,
                "violation": None,
                "metadata": {},
            }

            with patch("cpex.framework.isolated.client.get_hook_registry") as mock_registry:
                # Import the appropriate result type
                if "Tool" in result_type_name:
                    from cpex.framework.hooks.tools import ToolPostInvokeResult, ToolPreInvokeResult

                    result_class = ToolPreInvokeResult if "Pre" in result_type_name else ToolPostInvokeResult
                else:
                    from cpex.framework.hooks.prompts import PromptPosthookResult, PromptPrehookResult

                    result_class = PromptPrehookResult if "Pre" in result_type_name else PromptPosthookResult

                mock_reg = MagicMock()
                mock_reg.get_result_type.return_value = result_class
                mock_registry.return_value = mock_reg

                # Create appropriate payload
                if "tool" in hook_type:
                    from cpex.framework.hooks.tools import ToolPostInvokePayload, ToolPreInvokePayload

                    payload = (
                        ToolPreInvokePayload(name="test", args={})
                        if "pre" in hook_type
                        else ToolPostInvokePayload(name="test", result={})
                    )
                else:
                    from cpex.framework.hooks.prompts import PromptPosthookPayload, PromptPrehookPayload

                    payload = (
                        PromptPrehookPayload(prompt_id="test", args={})
                        if "pre" in hook_type
                        else PromptPosthookPayload(prompt_id="test", result={})
                    )

                global_ctx = GlobalContext(request_id="req-123")
                from cpex.framework.models import PluginContext

                context = PluginContext(global_context=global_ctx)

                result = await plugin.invoke_hook(hook_type, payload, context)
                assert result is not None

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_isolated_plugin_context_propagation(self, mock_create_venv, mock_comm_class, tmp_path):
        """Test that context is properly propagated through isolated plugin."""
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm.install_requirements = MagicMock()

        # Capture the task data sent
        captured_task = None

        def capture_task(script_path, task_data, max_content_size):
            nonlocal captured_task
            captured_task = task_data
            return {"continue_processing": True, "modified_payload": None, "violation": None, "metadata": {}}

        mock_comm.send_task = capture_task
        mock_comm_class.return_value = mock_comm

        config_dict = {
            "name": "test_plugin",
            "kind": "isolated_venv",
            "description": "Test plugin",
            "version": "1.0.0",
            "author": "Test",
            "hooks": ["tool_pre_invoke"],
            "config": {
                "class_name": "test_plugin.TestPlugin",
                "requirements_file": "requirements.txt",
            },
        }
        config = PluginConfig(**config_dict)
        resolved_plugin_path = (tmp_path / "xplugins").resolve()
        cache_root = resolved_plugin_path / "test_plugin"
        cache_root.mkdir(parents=True, exist_ok=True)

        plugin = IsolatedVenvPlugin(config, plugin_dirs=[str(resolved_plugin_path)])

        await plugin.initialize()

        with patch("cpex.framework.isolated.client.get_hook_registry") as mock_registry:
            from cpex.framework.hooks.tools import ToolPreInvokeResult

            mock_reg = MagicMock()
            mock_reg.get_result_type.return_value = ToolPreInvokeResult
            mock_registry.return_value = mock_reg

            # Create context with metadata
            global_ctx = GlobalContext(request_id="req-123", user="alice", tenant_id="tenant-1")
            from cpex.framework.models import PluginContext

            context = PluginContext(global_context=global_ctx, state={"key": "value"}, metadata={"custom": "data"})

            payload = ToolPreInvokePayload(name="test_tool", args={"arg1": "value1"})

            await plugin.invoke_hook("tool_pre_invoke", payload, context)

            # Verify context was properly serialized and sent
            assert captured_task is not None
            assert "context" in captured_task
            assert captured_task["context"]["global_context"]["request_id"] == "req-123"
            assert captured_task["context"]["global_context"]["user"] == "alice"
            assert captured_task["context"]["state"]["key"] == "value"
            assert captured_task["context"]["metadata"]["custom"] == "data"

            # Verify payload was serialized
            assert "payload" in captured_task
            assert captured_task["payload"]["name"] == "test_tool"
            assert captured_task["payload"]["args"]["arg1"] == "value1"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_isolated_plugin_violation_handling(self, mock_create_venv, mock_comm_class, tmp_path):
        """Test handling of policy violations in isolated plugin."""
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm.install_requirements = MagicMock()
        mock_comm.send_task.return_value = {
            "continue_processing": False,
            "modified_payload": None,
            "violation": {"reason": "Policy violation", "description": "severity high", "code": "PROHIBITED_CONTENT"},
            "metadata": {},
        }
        mock_comm_class.return_value = mock_comm

        config_dict = {
            "name": "test_plugin",
            "kind": "isolated_venv",
            "description": "Test plugin",
            "version": "1.0.0",
            "author": "Test",
            "hooks": ["tool_pre_invoke"],
            "config": {
                "class_name": "test_plugin.TestPlugin",
                "requirements_file": "requirements.txt",
            },
        }
        config = PluginConfig(**config_dict)
        resolved_plugin_path = (tmp_path / "xplugins").resolve()
        cache_root = resolved_plugin_path / "test_plugin"
        cache_root.mkdir(parents=True, exist_ok=True)

        plugin = IsolatedVenvPlugin(config, plugin_dirs=[str(resolved_plugin_path)])

        await plugin.initialize()

        with patch("cpex.framework.isolated.client.get_hook_registry") as mock_registry:
            from cpex.framework.hooks.tools import ToolPreInvokeResult

            mock_reg = MagicMock()
            mock_reg.get_result_type.return_value = ToolPreInvokeResult
            mock_reg.json_to_result = MagicMock()
            mock_reg.json_to_result.return_value = ToolPreInvokeResult(
                continue_processing=False,
                violation={"reason": "Policy violation", "description": "severity high", "code": "PROHIBITED_CONTENT"},
            )
            mock_registry.return_value = mock_reg

            payload = ToolPreInvokePayload(name="dangerous_tool", args={})
            global_ctx = GlobalContext(request_id="req-123")
            from cpex.framework.models import PluginContext

            context = PluginContext(global_context=global_ctx)

            result = await plugin.invoke_hook("tool_pre_invoke", payload, context)

            assert result.continue_processing is False
            assert result.violation is not None


class TestFqnAutoConversionAcceptance:
    """U7 acceptance: regression + bare-FQN conversion end-to-end (R7)."""

    FQN_MANIFEST = {
        "name": "fqn-plugin",
        "kind": "fqn_plugin.plugin.FqnPlugin",  # bare FQN, not a known kind
        "description": "A synthetic bare-FQN plugin fixture",
        "author": "habeck",
        "version": "0.1.0",
        "tags": ["test"],
        "available_hooks": ["tool_pre_invoke"],
        "default_configs": {},  # legacy plural key, no requirements_file
    }

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_regression_existing_isolated_plugin_still_loads(
        self, mock_create_venv, mock_comm_class, tmp_path
    ):
        """Regression: an already-isolated_venv plugin initializes and invokes unchanged (R7.1)."""
        mock_create_venv.return_value = None
        mock_comm = MagicMock()
        mock_comm.send_task.return_value = {
            "continue_processing": True,
            "modified_payload": None,
            "violation": None,
            "metadata": {},
        }
        mock_comm_class.return_value = mock_comm

        config = PluginConfig(
            name="test_plugin",
            kind="isolated_venv",
            description="Test plugin",
            version="1.0.0",
            author="Test",
            hooks=["tool_pre_invoke"],
            config={"class_name": "test_plugin.TestPlugin", "requirements_file": "requirements.txt"},
        )
        resolved = (tmp_path / "xplugins").resolve()
        (resolved / "test_plugin").mkdir(parents=True, exist_ok=True)
        plugin = IsolatedVenvPlugin(config, plugin_dirs=[resolved])

        with patch("cpex.framework.isolated.client.get_hook_registry") as mock_registry:
            from cpex.framework.hooks.tools import ToolPreInvokeResult
            from cpex.framework.models import PluginContext

            mock_reg = MagicMock()
            mock_reg.get_result_type.return_value = ToolPreInvokeResult
            mock_reg.json_to_result.return_value = ToolPreInvokeResult(continue_processing=True)
            mock_registry.return_value = mock_reg

            await plugin.initialize()
            context = PluginContext(global_context=GlobalContext(request_id="req-1"))
            result = await plugin.invoke_hook(
                "tool_pre_invoke", ToolPreInvokePayload(name="t", args={}), context
            )
            assert result.continue_processing is True

    def test_fqn_manifest_converts_and_persists(self, tmp_path, monkeypatch):
        """A bare-FQN manifest converts to isolated_venv + class_name and persists to plugin dir (R2, R3)."""
        from cpex.tools.catalog import PluginCatalog

        monkeypatch.setenv("PLUGINS_GITHUB_TOKEN", "test_token")
        with patch("cpex.tools.catalog.Github"):
            catalog = PluginCatalog()
            catalog.plugin_folder = str(tmp_path / "plugins")

            manifest = catalog._normalize_manifest_data(dict(self.FQN_MANIFEST), "fqn-plugin", None)

            # Converted in memory.
            assert manifest.kind == "isolated_venv"
            assert manifest.default_config["class_name"] == "fqn_plugin.plugin.FqnPlugin"

            # Persisted under plugins/<class_root>/ with a per-full-class-name
            # filename (so multi-plugin packages don't collide — see #4).
            from cpex.framework.utils import manifest_filename_for_class

            written_path = catalog._persist_manifest_to_plugin_dir(manifest)
            expected = (
                tmp_path / "plugins" / "fqn_plugin" / manifest_filename_for_class("fqn_plugin.plugin.FqnPlugin")
            )
            assert written_path == expected
            persisted = yaml.safe_load(expected.read_text())
            assert persisted["kind"] == "isolated_venv"
            assert persisted["default_config"]["class_name"] == "fqn_plugin.plugin.FqnPlugin"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.client.VenvProcessCommunicator")
    @patch.object(IsolatedVenvPlugin, "create_venv")
    async def test_converted_fqn_plugin_executes_hook(self, mock_create_venv, mock_comm_class, tmp_path):
        """A converted FQN plugin (no requirements) initializes its venv and executes a hook (R4, R7.2)."""
        mock_create_venv.return_value = True  # newly created venv, no requirements to install
        mock_comm = MagicMock()
        mock_comm.send_task.return_value = {
            "continue_processing": True,
            "modified_payload": None,
            "violation": None,
            "metadata": {},
        }
        mock_comm_class.return_value = mock_comm

        # Config as it would appear after conversion: isolated_venv + class_name, no requirements_file.
        config = PluginConfig(
            name="fqn-plugin",
            kind="isolated_venv",
            description="A synthetic bare-FQN plugin fixture",
            version="0.1.0",
            author="habeck",
            hooks=["tool_pre_invoke"],
            config={"class_name": "fqn_plugin.plugin.FqnPlugin"},
        )
        resolved = (tmp_path / "xplugins").resolve()
        (resolved / "fqn_plugin").mkdir(parents=True, exist_ok=True)
        plugin = IsolatedVenvPlugin(config, plugin_dirs=[resolved])

        with patch("cpex.framework.isolated.client.get_hook_registry") as mock_registry:
            from cpex.framework.hooks.tools import ToolPreInvokeResult
            from cpex.framework.models import PluginContext

            mock_reg = MagicMock()
            mock_reg.get_result_type.return_value = ToolPreInvokeResult
            mock_reg.json_to_result.return_value = ToolPreInvokeResult(continue_processing=True)
            mock_registry.return_value = mock_reg

            # Must initialize without a requirements file (no KeyError) and skip install.
            await plugin.initialize()
            mock_comm.install_requirements.assert_not_called()

            context = PluginContext(global_context=GlobalContext(request_id="req-2"))
            result = await plugin.invoke_hook(
                "tool_pre_invoke", ToolPreInvokePayload(name="t", args={}), context
            )
            assert result.continue_processing is True

    def test_version_bump_invalidates_converted_plugin_cache(self, tmp_path):
        """Bumping a converted plugin's manifest version invalidates its venv cache (U5 + U6 tie-in)."""
        config = PluginConfig(
            name="fqn-plugin",
            kind="isolated_venv",
            description="d",
            version="0.1.0",
            author="habeck",
            hooks=["tool_pre_invoke"],
            config={"class_name": "fqn_plugin.plugin.FqnPlugin"},
        )
        resolved = (tmp_path / "xplugins").resolve()
        (resolved / "fqn_plugin").mkdir(parents=True, exist_ok=True)
        plugin = IsolatedVenvPlugin(config, plugin_dirs=[resolved])

        venv_path = plugin.plugin_path / ".venv"
        venv_path.mkdir(parents=True, exist_ok=True)
        plugin._save_cache_metadata(str(venv_path), None)
        assert plugin._is_venv_cache_valid(str(venv_path), None) is True

        # Simulate a version bump recorded in the metadata being stale.
        metadata_path = plugin._get_cache_metadata_path(str(venv_path))
        import json

        meta = json.loads(metadata_path.read_text())
        meta["manifest_version"] = "0.0.9"
        metadata_path.write_text(json.dumps(meta))
        assert plugin._is_venv_cache_valid(str(venv_path), None) is False


# Made with Bob
