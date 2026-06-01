# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_worker.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Unit tests for worker.py functions.
"""

import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cpex.framework.isolated.worker import TaskProcessor, get_environment_info, main, process_task


class TestWorkerFunctions:
    """Test suite for worker.py functions."""

    @pytest.fixture
    def mock_plugin_dirs(self):
        """ensure that the plugins directory exists"""
        plugin_dirs = Path(os.getcwd()) / "tmp" / "plugins"
        tmp = plugin_dirs
        tmp.mkdir(parents=True, exist_ok=True)
        return [str(plugin_dirs.resolve())]

    def cleanup_mock_plugin_dirs(self):
        """Test cleanup for the mock plugin directories."""
        plugin_root = Path(os.getcwd()) / "tmp"
        shutil.rmtree(plugin_root.resolve())

    def test_get_environment_info(self):
        """Test getting environment information."""
        info = get_environment_info()

        assert "python_version" in info
        assert "python_executable" in info
        assert "platform" in info
        assert "installed_packages" in info

        assert info["python_version"] == sys.version
        assert info["python_executable"] == sys.executable
        assert isinstance(info["installed_packages"], list)
        assert len(info["installed_packages"]) <= 10  # Limited to first 10

    @pytest.mark.asyncio
    async def test_process_task_info(self):
        """Test processing info task."""
        config_dict = {"name": "test_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {"task_type": "info", "config": json.dumps(config_dict)}
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert result["status"] == "success"
        assert "environment" in result
        assert "message" in result
        assert result["message"] == "Environment info retrieved successfully"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    @patch("cpex.framework.isolated.worker.PluginExecutor")
    async def test_process_task_load_and_run_hook_success(
        self, mock_executor_class, mock_import, mock_plugin_dirs
    ):
        """Test processing load_and_run_hook task successfully."""

        # Setup mock plugin class
        mock_plugin_instance = AsyncMock()
        mock_plugin_instance.initialize = AsyncMock()
        mock_plugin_instance.tool_pre_invoke = AsyncMock()
        mock_plugin_instance.tool_post_invoke = AsyncMock()
        mock_plugin_instance.tool_exception = AsyncMock()
        mock_plugin_instance.tool_cleanup = AsyncMock()
        mock_plugin_class = MagicMock(return_value=mock_plugin_instance)

        mock_module = MagicMock()
        mock_module.TestPlugin = mock_plugin_class
        mock_import.return_value = mock_module

        # Setup mock executor
        mock_executor = MagicMock()
        mock_result = MagicMock()
        mock_result.continue_processing = True
        mock_executor.execute_plugin = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor

        # Create task data
        config_dict = {"name": "test_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": "test_plugin.TestPlugin",
            "hook_type": "tool_pre_invoke",
            "payload": {"name": "test_tool", "args": {}},
            "context": {"state": {}, "global_context": {"request_id": "req-123"}, "metadata": {}},
        }
        tp = TaskProcessor()
        result = await process_task(task_data, tp=tp)

        assert result is not None
        mock_plugin_instance.initialize.assert_called_once()
        mock_executor.execute_plugin.assert_called_once()
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_process_task_load_and_run_hook_import_error(self, mock_import, mock_plugin_dirs):
        """Test processing load_and_run_hook task with import error."""
        mock_import.side_effect = ImportError("Module not found")

        config_dict = {"name": "test_plugin", "kind": "isolated_venv"}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "class_name": "test_plugin.TestPlugin",
            "plugin_dirs": mock_plugin_dirs,
            "hook_type": "tool_pre_invoke",
            "payload": {},
            "context": {"state": {}, "global_context": {}, "metadata": {}},
        }
        tp = TaskProcessor()
        with pytest.raises(ImportError):
            await process_task(task_data, tp)

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    @patch("cpex.framework.isolated.worker.PluginExecutor")
    async def test_process_task_with_different_hook_types(
        self, mock_executor_class, mock_import, mock_plugin_dirs
    ):
        """Test processing tasks with different hook types."""

        mock_plugin_instance = MagicMock()
        mock_plugin_instance.initialize = AsyncMock()
        mock_plugin_instance.tool_pre_invoke = AsyncMock()
        mock_plugin_instance.tool_post_invoke = AsyncMock()
        mock_plugin_instance.prompt_pre_fetch = AsyncMock()
        mock_plugin_instance.prompt_post_fetch = AsyncMock()
        mock_plugin_instance.tool_exception = AsyncMock()
        mock_plugin_instance.tool_cleanup = AsyncMock()
        mock_plugin_class = MagicMock(return_value=mock_plugin_instance)

        mock_module = MagicMock()
        mock_module.TestPlugin = mock_plugin_class
        mock_import.return_value = mock_module

        mock_executor = MagicMock()
        mock_result = MagicMock()
        mock_executor.execute_plugin = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor

        hook_types = ["tool_pre_invoke", "tool_post_invoke", "prompt_pre_fetch", "prompt_post_fetch"]
        tp = TaskProcessor()

        for hook_type in hook_types:
            config_dict = {"name": "test_plugin", "kind": "isolated_venv"}
            task_data = {
                "task_type": "load_and_run_hook",
                "config": json.dumps(config_dict),
                "plugin_dirs": mock_plugin_dirs,
                "class_name": "test_plugin.TestPlugin",
                "hook_type": hook_type,
                "payload": {},
                "context": {"state": {}, "global_context": {"request_id": "req-123"}, "metadata": {}},
            }
            result = await process_task(task_data, tp)
            assert result is not None
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    async def test_process_task_unknown_task_type(self):
        """Test processing task with unknown task type."""
        task_data = {"task_type": "unknown_type"}
        tp = TaskProcessor()
        # Should return None or handle gracefully
        result = await process_task(task_data, tp)
        assert result == {"message": "task type not supported.", "request_id": "unknown", "status": "error"}

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    @patch("cpex.framework.isolated.worker.PluginExecutor")
    async def test_process_task_with_metadata(
        self, mock_executor_class, mock_import, mock_plugin_dirs
    ):
        """Test processing task with metadata in context."""

        mock_plugin_instance = AsyncMock()
        mock_plugin_instance.initialize = AsyncMock()
        mock_plugin_instance.tool_pre_invoke = AsyncMock()
        mock_plugin_instance.tool_post_invoke = AsyncMock()
        mock_plugin_instance.prompt_pre_fetch = AsyncMock()
        mock_plugin_instance.prompt_post_fetch = AsyncMock()
        mock_plugin_instance.tool_exception = AsyncMock()
        mock_plugin_instance.tool_cleanup = AsyncMock()

        mock_plugin_class = MagicMock(return_value=mock_plugin_instance)

        mock_module = MagicMock()
        mock_module.TestPlugin = mock_plugin_class
        mock_import.return_value = mock_module

        mock_executor = MagicMock()
        mock_result = MagicMock()
        mock_executor.execute_plugin = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor

        config_dict = {"name": "test_plugin", "kind": "isolated_venv"}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "class_name": "test_plugin.TestPlugin",
            "plugin_dirs": mock_plugin_dirs,
            "hook_type": "tool_pre_invoke",
            "payload": {"name": "test_tool"},
            "context": {
                "state": {"key": "value"},
                "global_context": {"request_id": "req-123", "user": "alice"},
                "metadata": {"custom": "data"},
            },
        }
        tp = TaskProcessor()

        result = await process_task(task_data, tp)

        assert result is not None
        # Verify executor was called with proper context
        call_args = mock_executor.execute_plugin.call_args
        assert call_args is not None
        self.cleanup_mock_plugin_dirs()


class TestMainFunction:
    """Test suite for the main() function."""

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_success_with_info_task(self, mock_process_task, mock_print, mock_stdin):
        """Test main function with successful info task."""
        # Setup stdin to return one task then EOF
        task_data = {"task_type": "info", "request_id": "req-123"}
        mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]  # EOF after first task

        # Setup process_task to return a mock result
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "status": "success",
            "environment": {"python_version": "3.10"},
            "message": "Environment info retrieved successfully",
        }
        mock_process_task.return_value = mock_result

        # Run main
        await main()

        # Verify process_task was called with correct data
        mock_process_task.assert_called_once()
        call_args = mock_process_task.call_args[0][0]
        assert call_args["task_type"] == "info"
        assert call_args["request_id"] == "req-123"

        # Verify output was printed with request_id
        mock_print.assert_called_once()
        printed_output = mock_print.call_args[0][0]
        output_data = json.loads(printed_output)
        assert output_data["status"] == "success"
        assert output_data["request_id"] == "req-123"

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_success_with_none_result(self, mock_process_task, mock_print, mock_stdin):
        """Test main function when process_task returns None."""
        task_data = {"task_type": "unknown", "request_id": "req-456"}
        mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]

        # process_task returns None for unknown task types
        mock_process_task.return_value = None

        await main()

        mock_process_task.assert_called_once()
        mock_print.assert_called_once()
        printed_output = mock_print.call_args[0][0]
        output_data = json.loads(printed_output)
        # Should have success status and request_id
        assert output_data["status"] == "success"
        assert output_data["request_id"] == "req-456"

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    async def test_main_json_decode_error(self, mock_print, mock_stdin):
        """Test main function with invalid JSON input."""
        # Setup stdin with invalid JSON then EOF
        mock_stdin.readline.side_effect = ["not valid json {{", ""]

        await main()

        # Verify error response was printed
        mock_print.assert_called()
        printed_output = mock_print.call_args_list[0][0][0]
        output_data = json.loads(printed_output)
        assert output_data["status"] == "error"
        assert "Invalid JSON input" in output_data["message"]

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_unexpected_exception(self, mock_process_task, mock_print, mock_stdin):
        """Test main function with unexpected exception during processing."""
        task_data = {"task_type": "load_and_run_hook", "request_id": "req-789"}
        mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]

        # Make process_task raise an exception
        mock_process_task.side_effect = RuntimeError("Unexpected error occurred")

        await main()

        # Verify error response was printed
        mock_print.assert_called()
        printed_output = mock_print.call_args_list[0][0][0]
        output_data = json.loads(printed_output)
        assert output_data["status"] == "error"
        assert "Unexpected error: Unexpected error occurred" in output_data["message"]
        assert output_data["request_id"] == "unknown"

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_with_load_and_run_hook_task(self, mock_process_task, mock_print, mock_stdin):
        """Test main function with load_and_run_hook task."""
        config_dict = {"name": "test_plugin", "kind": "isolated_venv"}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "class_name": "test_plugin.TestPlugin",
            "hook_type": "tool_pre_invoke",
            "payload": {"name": "test_tool"},
            "context": {"state": {}, "global_context": {}, "metadata": {}},
            "request_id": "req-abc",
        }
        mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]

        # Setup mock result
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "continue_processing": True,
            "payload": {"name": "test_tool", "modified": True},
            "violations": [],
        }
        mock_process_task.return_value = mock_result

        await main()

        mock_process_task.assert_called_once()
        mock_print.assert_called_once()
        printed_output = mock_print.call_args[0][0]
        output_data = json.loads(printed_output)
        assert output_data["continue_processing"] is True
        assert output_data["request_id"] == "req-abc"

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    async def test_main_with_empty_line(self, mock_print, mock_stdin):
        """Test main function with empty line (EOF)."""
        mock_stdin.readline.return_value = ""

        await main()

        # Should exit gracefully without printing error
        # (may not print anything if EOF is first thing read)

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_with_model_dump_exception(self, mock_process_task, mock_print, mock_stdin):
        """Test main function when model_dump raises an exception."""
        task_data = {"task_type": "info", "request_id": "req-error"}
        mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]

        # Setup mock result that raises exception on model_dump
        mock_result = MagicMock()
        mock_result.model_dump.side_effect = ValueError("Cannot serialize")
        mock_process_task.return_value = mock_result

        await main()

        # Should catch the exception and return error
        mock_print.assert_called()
        printed_output = mock_print.call_args_list[0][0][0]
        output_data = json.loads(printed_output)
        assert output_data["status"] == "error"
        assert "Unexpected error" in output_data["message"]

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    async def test_main_with_shutdown_signal(self, mock_print, mock_stdin):
        """Test main function with shutdown signal."""
        task_data = {"task_type": "shutdown", "request_id": "shutdown"}
        mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]

        await main()

        # Should print shutdown response and exit
        mock_print.assert_called_once()
        printed_output = mock_print.call_args[0][0]
        output_data = json.loads(printed_output)
        assert output_data["status"] == "success"
        assert output_data["message"] == "Shutting down"
        assert output_data["request_id"] == "shutdown"

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_multiple_tasks(self, mock_process_task, mock_print, mock_stdin):
        """Test main function processing multiple tasks."""
        task1 = {"task_type": "info", "request_id": "req-1"}
        task2 = {"task_type": "info", "request_id": "req-2"}
        mock_stdin.readline.side_effect = [
            json.dumps(task1) + "\n",
            json.dumps(task2) + "\n",
            "",  # EOF
        ]

        mock_result = MagicMock()
        mock_result.model_dump.return_value = {"status": "success"}
        mock_process_task.return_value = mock_result

        await main()

        # Should process both tasks
        assert mock_process_task.call_count == 2
        assert mock_print.call_count == 2


# Made with Bob
