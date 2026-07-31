# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/test_worker.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Unit tests for worker.py functions.
"""

import json
import logging
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
        # json_to_payload is a synchronous method; without this override the
        # AsyncMock parent would auto-create it as an AsyncMock, and process_task
        # calls it without awaiting (worker.py) — leaking an unawaited coroutine.
        mock_plugin_instance.json_to_payload = MagicMock()
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
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_process_task_deserializes_payload_to_typed_object(self, mock_import, mock_plugin_dirs):
        """Regression: the worker must reconstruct the typed payload before invoking the plugin.

        The client serializes the payload with ``model_dump(mode="json")``, so it
        arrives at the worker as a plain dict. Previously the worker passed that
        dict straight to the plugin hook, which then failed with
        ``AttributeError("'dict' object has no attribute 'args'")`` the moment the
        hook touched ``payload.args``. This test drives a real Plugin subclass
        through ``process_task`` and asserts the hook receives a genuine
        ``ToolPreInvokePayload`` with a working ``.args`` attribute.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.tools import ToolPreInvokePayload, ToolPreInvokeResult

        received = {}

        class RealTypedPlugin(Plugin):
            """Minimal real plugin that asserts payload typing at runtime."""

            async def tool_pre_invoke(self, payload, context, extensions=None):
                # Would raise AttributeError before the fix, when payload is a dict.
                received["type"] = type(payload)
                received["args"] = payload.args
                received["name"] = payload.name
                return ToolPreInvokeResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.RealTypedPlugin = RealTypedPlugin
        mock_import.return_value = mock_module

        config_dict = {"name": "typed_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": "typed_plugin.RealTypedPlugin",
            "hook_type": "tool_pre_invoke",
            # Payload exactly as the client sends it: model_dump(mode="json") output.
            "payload": {"name": "web_search", "args": {"query": "CPEX framework"}},
            "context": {"state": {}, "global_context": {"request_id": "req-123"}, "metadata": {}},
        }
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert result is not None
        assert result.continue_processing is True
        # The hook must have received a typed payload, not a dict.
        assert received["type"] is ToolPreInvokePayload
        assert received["name"] == "web_search"
        assert received["args"] == {"query": "CPEX framework"}
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    @patch("cpex.framework.isolated.worker.PluginExecutor")
    async def test_process_task_none_payload_passes_through(
        self, mock_executor_class, mock_import, mock_plugin_dirs
    ):
        """A None payload must be forwarded as None, not run through json_to_payload."""
        mock_plugin_instance = AsyncMock()
        mock_plugin_instance.initialize = AsyncMock()
        mock_plugin_instance.json_to_payload = MagicMock()
        mock_plugin_class = MagicMock(return_value=mock_plugin_instance)

        mock_module = MagicMock()
        mock_module.TestPlugin = mock_plugin_class
        mock_import.return_value = mock_module

        mock_executor = MagicMock()
        mock_result = MagicMock()
        mock_executor.execute_plugin = AsyncMock(return_value=mock_result)
        mock_executor_class.return_value = mock_executor

        config_dict = {"name": "test_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": "test_plugin.TestPlugin",
            "hook_type": "tool_pre_invoke",
            "payload": None,
            "context": {"state": {}, "global_context": {"request_id": "req-123"}, "metadata": {}},
        }
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert result is not None
        # json_to_payload must not be invoked for a None payload.
        mock_plugin_instance.json_to_payload.assert_not_called()
        # execute_plugin must have been called with payload=None.
        _, call_kwargs = mock_executor.execute_plugin.call_args
        assert call_kwargs["payload"] is None
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
        # json_to_payload is synchronous — keep it a MagicMock so the AsyncMock
        # parent doesn't auto-create it as a coroutine that process_task never awaits.
        mock_plugin_instance.json_to_payload = MagicMock()

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


class TestIdentityHookRegistration:
    """The worker must register the identity hooks it exists to serve."""

    def test_worker_import_registers_identity_hooks(self):
        """Importing the worker makes identity_resolve/token_delegate resolvable.

        ``cpex.framework.hooks.identity`` registers its hooks as an import-time
        side effect, and ``cpex.framework.__init__`` does not import it (unlike
        hooks.tools / prompts / resources / agents / http). Without the worker
        importing it explicitly, ``json_to_payload`` raises "No payload defined
        for hook identity_resolve" and no out-of-process identity or delegation
        plugin can run at all — credential field or not.

        This asserts against a subprocess that imports *only* the worker, because
        an in-process assertion is worthless here: any other test importing
        hooks.identity would register the hooks and mask the gap.
        """
        import subprocess

        script = (
            "import cpex.framework.isolated.worker\n"
            "from cpex.framework.hooks.registry import get_hook_registry\n"
            "r = get_hook_registry()\n"
            "assert r.is_registered('identity_resolve'), 'identity_resolve not registered'\n"
            "assert r.is_registered('token_delegate'), 'token_delegate not registered'\n"
            "print('OK')\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[5]),
        )
        assert completed.returncode == 0, f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
        assert "OK" in completed.stdout


class TestCredentialReconstruction:
    """Credential field read and payload reconstruction (identity/delegation hooks).

    ``IdentityPayload.raw_token`` and ``DelegationPayload.bearer_token`` are
    ``SecretStr``, which redacts on serialization — so the plaintext token the
    Rust host holds never survives into the JSON payload the worker
    deserializes. The worker must source the plaintext from a separate
    ``credential`` task field and rebuild the payload with it.
    """

    @pytest.fixture
    def mock_plugin_dirs(self):
        """Ensure the plugins directory exists."""
        plugin_dirs = Path(os.getcwd()) / "tmp" / "plugins"
        plugin_dirs.mkdir(parents=True, exist_ok=True)
        return [str(plugin_dirs.resolve())]

    def cleanup_mock_plugin_dirs(self):
        """Test cleanup for the mock plugin directories."""
        shutil.rmtree((Path(os.getcwd()) / "tmp").resolve(), ignore_errors=True)

    @staticmethod
    def _identity_task(mock_plugin_dirs, credential=None, class_name="cred_plugin.RecordingIdentityPlugin"):
        """Build an identity_resolve task, optionally carrying a credential field."""
        config_dict = {"name": "cred_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": class_name,
            "hook_type": "identity_resolve",
            # Payload exactly as the client sends it: model_dump(mode="json"),
            # so raw_token arrives redacted.
            "payload": {"raw_token": "**********", "source": "bearer", "headers": {}},
            "context": {"state": {}, "global_context": {"request_id": "req-cred"}, "metadata": {}},
        }
        if credential is not None:
            task_data["credential"] = credential
        return task_data

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_identity_resolve_receives_plaintext_token(self, mock_import, mock_plugin_dirs):
        """An identity_resolve task with a credential field delivers the plaintext token.

        The hook must see ``raw_token.get_secret_value()`` equal to the
        credential field's token, with ``source`` and ``headers`` populated.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.identity import IdentityPayload, IdentityResolveResult, IdentityResult

        received = {}

        class RecordingIdentityPlugin(Plugin):
            """Records what the identity hook actually observed on its payload."""

            async def identity_resolve(self, payload, context, extensions=None):
                received["type"] = type(payload)
                received["token"] = payload.raw_token.get_secret_value()
                received["source"] = payload.source
                received["headers"] = dict(payload.headers)
                return IdentityResolveResult(continue_processing=True, modified_payload=IdentityResult())

        mock_module = MagicMock()
        mock_module.RecordingIdentityPlugin = RecordingIdentityPlugin
        mock_import.return_value = mock_module

        task_data = self._identity_task(
            mock_plugin_dirs,
            credential={
                "inbound": {
                    "token": "eyJhbGciOi.PLAINTEXT.sig",
                    "source_header": "Authorization",
                    "kind": "jwt",
                }
            },
        )
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert result is not None
        assert result.continue_processing is True
        assert received["type"] is IdentityPayload
        assert received["token"] == "eyJhbGciOi.PLAINTEXT.sig"
        assert received["source"] == "bearer"
        # headers were absent on the redacted payload, so the worker synthesizes
        # the *name* of the carrying header — but not its value. headers is
        # dict[str, str] and does not redact on serialization, so the plaintext
        # stays on raw_token only.
        assert received["headers"] == {"Authorization": "**********"}
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_identity_resolve_forwards_supplied_headers_scrubbed(self, mock_import, mock_plugin_dirs):
        """Host-supplied headers are forwarded, but with the plaintext scrubbed.

        Non-credential headers pass through untouched; a header value carrying the
        token is replaced, because ``headers`` does not redact on serialization.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.identity import IdentityResolveResult, IdentityResult

        received = {}

        class RecordingIdentityPlugin(Plugin):
            """Records the headers the identity hook observed."""

            async def identity_resolve(self, payload, context, extensions=None):
                received["headers"] = dict(payload.headers)
                received["token"] = payload.raw_token.get_secret_value()
                return IdentityResolveResult(continue_processing=True, modified_payload=IdentityResult())

        mock_module = MagicMock()
        mock_module.RecordingIdentityPlugin = RecordingIdentityPlugin
        mock_import.return_value = mock_module

        task_data = self._identity_task(
            mock_plugin_dirs,
            credential={
                "inbound": {
                    "token": "opaque-token-value",
                    "source_header": "X-Api-Key",
                    "kind": "api_key",
                    "headers": {
                        "X-Api-Key": "opaque-token-value",
                        "Authorization": "Bearer opaque-token-value",
                        "X-Trace": "abc",
                    },
                }
            },
        )
        tp = TaskProcessor()
        await process_task(task_data, tp)

        # The plaintext still reaches the hook — on the SecretStr field.
        assert received["token"] == "opaque-token-value"
        assert received["headers"] == {
            # Value equal to the token: fully replaced.
            "X-Api-Key": "**********",
            # Value embedding the token: scheme prefix survives, credential does not.
            "Authorization": "Bearer **********",
            # Unrelated header: untouched.
            "X-Trace": "abc",
        }
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_token_delegate_receives_plaintext_bearer_token(self, mock_import, mock_plugin_dirs):
        """A token_delegate task with a credential field delivers the plaintext bearer token."""
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.identity import DelegationPayload, DelegationResult, TokenDelegateResult

        received = {}

        class RecordingDelegationPlugin(Plugin):
            """Records what the delegation hook observed on its payload."""

            async def token_delegate(self, payload, context, extensions=None):
                received["type"] = type(payload)
                received["token"] = payload.bearer_token.get_secret_value()
                received["target"] = payload.target_name
                return TokenDelegateResult(continue_processing=True, modified_payload=DelegationResult())

        mock_module = MagicMock()
        mock_module.RecordingDelegationPlugin = RecordingDelegationPlugin
        mock_import.return_value = mock_module

        config_dict = {"name": "cred_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": "cred_plugin.RecordingDelegationPlugin",
            "hook_type": "token_delegate",
            "payload": {"target_name": "get_compensation", "target_type": "tool", "bearer_token": "**********"},
            "context": {"state": {}, "global_context": {"request_id": "req-cred"}, "metadata": {}},
            "credential": {
                "delegated": {
                    "token": "delegated.PLAINTEXT.jwt",
                    "outbound_header": "Authorization",
                    "audience": "hr-service",
                    "scopes": ["read:compensation"],
                }
            },
        }
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert result is not None
        assert received["type"] is DelegationPayload
        assert received["token"] == "delegated.PLAINTEXT.jwt"
        assert received["target"] == "get_compensation"
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    @patch("cpex.framework.isolated.worker.PluginExecutor")
    async def test_non_identity_hook_payload_untouched(
        self, mock_executor_class, mock_import, mock_plugin_dirs
    ):
        """A credential field on a non-identity/delegation hook triggers no reconstruction.

        Raw credentials are delivered exclusively for identity_resolve and
        token_delegate; any other hook's payload passes through as-is.
        """
        from cpex.framework.hooks.tools import ToolPreInvokePayload

        mock_plugin_instance = AsyncMock()
        mock_plugin_instance.initialize = AsyncMock()
        mock_plugin_instance.json_to_payload = MagicMock(
            return_value=ToolPreInvokePayload(name="web_search", args={})
        )
        mock_module = MagicMock()
        mock_module.TestPlugin = MagicMock(return_value=mock_plugin_instance)
        mock_import.return_value = mock_module

        mock_executor = MagicMock()
        mock_executor.execute_plugin = AsyncMock(return_value=MagicMock())
        mock_executor_class.return_value = mock_executor

        config_dict = {"name": "test_plugin", "kind": "isolated_venv", "config": {}}
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": "test_plugin.TestPlugin",
            "hook_type": "tool_pre_invoke",
            "payload": {"name": "web_search", "args": {}},
            "context": {"state": {}, "global_context": {"request_id": "req-cred"}, "metadata": {}},
            "credential": {"inbound": {"token": "should-be-ignored", "source_header": "Authorization"}},
        }
        tp = TaskProcessor()
        await process_task(task_data, tp)

        _, call_kwargs = mock_executor.execute_plugin.call_args
        forwarded = call_kwargs["payload"]
        # The payload json_to_payload produced is forwarded unchanged.
        assert forwarded == ToolPreInvokePayload(name="web_search", args={})
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_identity_resolve_without_credential_field_passes_through(
        self, mock_import, mock_plugin_dirs
    ):
        """Reconstruction is opt-in on the credential field's presence.

        An identity_resolve task with no credential field is not an error — the
        redacted payload is forwarded as-is.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.identity import IdentityResolveResult, IdentityResult

        received = {}

        class RecordingIdentityPlugin(Plugin):
            """Records the token the identity hook observed."""

            async def identity_resolve(self, payload, context, extensions=None):
                received["token"] = payload.raw_token.get_secret_value()
                return IdentityResolveResult(continue_processing=True, modified_payload=IdentityResult())

        mock_module = MagicMock()
        mock_module.RecordingIdentityPlugin = RecordingIdentityPlugin
        mock_import.return_value = mock_module

        task_data = self._identity_task(mock_plugin_dirs, credential=None)
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert result is not None
        assert result.continue_processing is True
        # No plaintext source, so the hook sees only what the redacted payload carried.
        assert received["token"] == "**********"
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_reconstructed_payload_result_serializes_back(self, mock_import, mock_plugin_dirs):
        """The reconstructed payload flows through execute_plugin and the result serializes.

        Integration-shaped: real Plugin, real executor, real result model — the
        response the worker's main loop would serialize must round-trip to JSON
        without the plaintext token appearing in it.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.extensions.security import SubjectExtension
        from cpex.framework.hooks.identity import IdentityResolveResult, IdentityResult

        token = "round.TRIP.token"

        class ResolvingIdentityPlugin(Plugin):
            """Resolves a subject from the plaintext token it received."""

            async def identity_resolve(self, payload, context, extensions=None):
                assert payload.raw_token.get_secret_value() == token
                return IdentityResolveResult(
                    continue_processing=True,
                    modified_payload=IdentityResult(
                        subject=SubjectExtension(id="alice@corp.com", type="user"),
                    ),
                )

        mock_module = MagicMock()
        mock_module.ResolvingIdentityPlugin = ResolvingIdentityPlugin
        mock_import.return_value = mock_module

        task_data = self._identity_task(
            mock_plugin_dirs,
            credential={"inbound": {"token": token, "source_header": "Authorization", "kind": "jwt"}},
            class_name="cred_plugin.ResolvingIdentityPlugin",
        )
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        serialized = json.dumps(result.model_dump(mode="json"))
        assert "alice@corp.com" in serialized
        # The plaintext token must not ride back out on the response.
        assert token not in serialized
        self.cleanup_mock_plugin_dirs()


class TestCredentialFailClosed:
    """Fail-closed behavior when a credential field cannot yield a usable token.

    Proceeding with an empty ``SecretStr`` would hand the plugin a credential
    that authenticates downstream as an empty bearer, so the worker must return
    an error instead — and that error must not echo the field's contents.
    """

    @pytest.fixture
    def mock_plugin_dirs(self):
        """Ensure the plugins directory exists."""
        plugin_dirs = Path(os.getcwd()) / "tmp" / "plugins"
        plugin_dirs.mkdir(parents=True, exist_ok=True)
        return [str(plugin_dirs.resolve())]

    def cleanup_mock_plugin_dirs(self):
        """Test cleanup for the mock plugin directories."""
        shutil.rmtree((Path(os.getcwd()) / "tmp").resolve(), ignore_errors=True)

    @staticmethod
    def _task(mock_plugin_dirs, hook_type, payload, credential):
        """Build a credential-bearing task for the given hook."""
        config_dict = {"name": "cred_plugin", "kind": "isolated_venv", "config": {}}
        return {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": "cred_plugin.NeverCalledPlugin",
            "hook_type": hook_type,
            "payload": payload,
            "context": {"state": {}, "global_context": {"request_id": "req-fail"}, "metadata": {}},
            "credential": credential,
            "request_id": "req-fail",
        }

    @pytest.fixture
    def never_called_plugin(self):
        """A plugin whose hooks fail the test if they are ever reached."""
        from cpex.framework.base import Plugin

        class NeverCalledPlugin(Plugin):
            """Fails loudly if a fail-closed path still reaches the hook."""

            async def identity_resolve(self, payload, context, extensions=None):
                raise AssertionError("identity_resolve must not run when reconstruction fails")

            async def token_delegate(self, payload, context, extensions=None):
                raise AssertionError("token_delegate must not run when reconstruction fails")

        return NeverCalledPlugin

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_empty_token_yields_error_and_skips_execute(
        self, mock_import, mock_plugin_dirs, never_called_plugin
    ):
        """An empty token yields an error response; the hook is never invoked."""
        mock_module = MagicMock()
        mock_module.NeverCalledPlugin = never_called_plugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {"inbound": {"token": "", "source_header": "Authorization", "kind": "jwt"}},
        )
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert isinstance(result, dict)
        assert result["status"] == "error"
        assert "Credential reconstruction failed" in result["message"]
        assert result["request_id"] == "req-fail"
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_delegation_empty_token_yields_error(
        self, mock_import, mock_plugin_dirs, never_called_plugin
    ):
        """The delegation path fails closed on an empty token too."""
        mock_module = MagicMock()
        mock_module.NeverCalledPlugin = never_called_plugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            "token_delegate",
            {"target_name": "get_compensation", "bearer_token": "**********"},
            {"delegated": {"token": "", "outbound_header": "Authorization"}},
        )
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert isinstance(result, dict)
        assert result["status"] == "error"
        assert "Credential reconstruction failed" in result["message"]
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "credential",
        [
            pytest.param({"inbound": {"source_header": "Authorization"}}, id="token-key-missing"),
            pytest.param({"inbound": {"token": None}}, id="token-null"),
            pytest.param({"inbound": {"token": 12345}}, id="token-not-a-string"),
            pytest.param({"inbound": "not-an-object"}, id="inbound-not-an-object"),
            pytest.param({}, id="inbound-missing"),
            pytest.param({"delegated": {"token": "wrong-sub-field"}}, id="wrong-sub-field-for-hook"),
            pytest.param("not-an-object", id="credential-not-an-object"),
            pytest.param([{"token": "in-a-list"}], id="credential-is-a-list"),
        ],
    )
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_malformed_credential_yields_error_not_escaping_exception(
        self, mock_import, credential, mock_plugin_dirs, never_called_plugin
    ):
        """A malformed credential field yields a clean error response.

        It must not raise past process_task into main()'s generic handler,
        whose message is a plain interpolation of str(e) and therefore a
        weaker containment boundary.
        """
        mock_module = MagicMock()
        mock_module.NeverCalledPlugin = never_called_plugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            credential,
        )
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        assert isinstance(result, dict), "reconstruction failure must return, not raise"
        assert result["status"] == "error"
        assert "Credential reconstruction failed" in result["message"]
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_fail_closed_error_contains_no_token_adjacent_values(
        self, mock_import, mock_plugin_dirs, never_called_plugin
    ):
        """The fail-closed error names the shape problem, never a field value.

        A partially-populated credential (non-empty sibling fields, unusable
        token) is the case where a naive ``str(credential)`` in the error would
        leak. Nothing from the field may appear in the response.
        """
        mock_module = MagicMock()
        mock_module.NeverCalledPlugin = never_called_plugin
        mock_import.return_value = mock_module

        secrets = ["SECRET-HEADER-NAME", "SECRET-KIND", "SECRET-HEADER-VALUE", "SECRET-AUD"]
        task_data = self._task(
            mock_plugin_dirs,
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {
                "inbound": {
                    "token": "",
                    "source_header": "SECRET-HEADER-NAME",
                    "kind": "SECRET-KIND",
                    "headers": {"Authorization": "SECRET-HEADER-VALUE"},
                    "audience": "SECRET-AUD",
                }
            },
        )
        tp = TaskProcessor()
        result = await process_task(task_data, tp)

        serialized = json.dumps(result)
        for secret in secrets:
            assert secret not in serialized, f"{secret} leaked into the fail-closed error response"
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_fail_closed_response_reaches_stdout_intact(self, mock_import, mock_plugin_dirs):
        """The fail-closed dict survives main()'s serialization to stdout.

        Regression guard: main() previously called ``response.model_dump()``
        unconditionally, so a dict return raised AttributeError into the generic
        handler and the real fail-closed message was replaced by a model_dump
        complaint — masking the security-relevant reason for the refusal.
        """
        from cpex.framework.base import Plugin

        class NeverCalledPlugin(Plugin):
            """Fails loudly if the hook is reached."""

            async def identity_resolve(self, payload, context, extensions=None):
                raise AssertionError("hook must not run")

        mock_module = MagicMock()
        mock_module.NeverCalledPlugin = NeverCalledPlugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            "identity_resolve",
            {"raw_token": "**********", "source": "bearer", "headers": {}},
            {"inbound": {"token": "", "source_header": "Authorization"}},
        )

        with patch("sys.stdin") as mock_stdin, patch("builtins.print") as mock_print:
            mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]
            await main()

        output = json.loads(mock_print.call_args_list[0][0][0])
        assert output["status"] == "error"
        assert "Credential reconstruction failed" in output["message"]
        assert output["request_id"] == "req-fail"
        self.cleanup_mock_plugin_dirs()


class TestCredentialRedactionHardening:
    """The plaintext credential must never reach stdout, logs, or stderr.

    This is the security core of credential delivery: the worker's stdout is the
    channel the host reads, its stderr is drained and logged by the reference
    ``venv_comm.py`` reader, and its ``logger`` output lands wherever the plugin
    venv configured logging. A single un-scrubbed interpolation on any of those
    three sinks leaks a live bearer token.
    """

    TOKEN = "LEAK-CANARY-eyJhbGciOi.SUPERSECRET.signature"

    @pytest.fixture
    def mock_plugin_dirs(self):
        """Ensure the plugins directory exists."""
        plugin_dirs = Path(os.getcwd()) / "tmp" / "plugins"
        plugin_dirs.mkdir(parents=True, exist_ok=True)
        return [str(plugin_dirs.resolve())]

    def cleanup_mock_plugin_dirs(self):
        """Test cleanup for the mock plugin directories."""
        shutil.rmtree((Path(os.getcwd()) / "tmp").resolve(), ignore_errors=True)

    def _task(self, mock_plugin_dirs, class_name):
        """Build a credential-bearing identity task carrying the canary token."""
        config_dict = {"name": "cred_plugin", "kind": "isolated_venv", "config": {}}
        return {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": class_name,
            "hook_type": "identity_resolve",
            "payload": {"raw_token": "**********", "source": "bearer", "headers": {}},
            "context": {"state": {}, "global_context": {"request_id": "req-leak"}, "metadata": {}},
            "credential": {
                "inbound": {
                    "token": self.TOKEN,
                    "source_header": "Authorization",
                    "kind": "jwt",
                }
            },
            "request_id": "req-leak",
        }

    @pytest.mark.asyncio
    async def test_exception_after_credential_read_leaks_nothing_to_stdout(
        self, mock_plugin_dirs, caplog, capsys
    ):
        """An exception raised while the plaintext is in scope leaks it nowhere.

        The plugin hook raises *after* the worker has reconstructed the payload,
        so the plaintext token is live in the worker's frame when the exception
        propagates through the executor and into main()'s generic handler, which
        both logs ``str(e)`` and echoes it to stdout.
        """
        from cpex.framework.base import Plugin

        class RaisingIdentityPlugin(Plugin):
            """Raises once the plaintext token is on its payload."""

            async def identity_resolve(self, payload, context, extensions=None):
                # Sanity: the plaintext really is in scope at raise time, so this
                # test exercises the leak path rather than a redacted no-op.
                assert payload.raw_token.get_secret_value() == TestCredentialRedactionHardening.TOKEN
                raise RuntimeError("downstream identity provider unreachable")

        task_data = self._task(mock_plugin_dirs, "cred_plugin.RaisingIdentityPlugin")

        mock_module = MagicMock()
        mock_module.RaisingIdentityPlugin = RaisingIdentityPlugin

        with caplog.at_level(logging.DEBUG):
            with patch("cpex.framework.isolated.worker.import_module", return_value=mock_module):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]
                    await main()

        captured = capsys.readouterr()
        assert self.TOKEN not in captured.out, "token leaked to stdout"
        assert self.TOKEN not in captured.err, "token leaked to stderr"
        assert self.TOKEN not in caplog.text, "token leaked into log output"
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    async def test_exception_message_embedding_the_token_is_scrubbed(
        self, mock_plugin_dirs, caplog, capsys
    ):
        """A plugin that interpolates the token into its own exception is contained.

        Worst case: the plugin itself builds the leak. ``str(e)`` then carries the
        plaintext directly, and the worker is the last boundary before stdout —
        so the worker must not forward raw exception text from a
        credential-bearing task.
        """
        from cpex.framework.base import Plugin

        class LeakyIdentityPlugin(Plugin):
            """Interpolates the plaintext token into its exception message."""

            async def identity_resolve(self, payload, context, extensions=None):
                raise ValueError(f"could not decode token {payload.raw_token.get_secret_value()}")

        task_data = self._task(mock_plugin_dirs, "cred_plugin.LeakyIdentityPlugin")

        mock_module = MagicMock()
        mock_module.LeakyIdentityPlugin = LeakyIdentityPlugin

        with caplog.at_level(logging.DEBUG):
            with patch("cpex.framework.isolated.worker.import_module", return_value=mock_module):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]
                    await main()

        captured = capsys.readouterr()
        assert self.TOKEN not in captured.out, "token leaked to stdout via exception message"
        assert self.TOKEN not in captured.err, "token leaked to stderr via exception message"
        assert self.TOKEN not in caplog.text, "token leaked into logs via exception message"
        # The caller still learns the request failed, and which request it was.
        output = json.loads(captured.out.strip().splitlines()[-1])
        assert output["status"] == "error"
        assert output["request_id"] == "req-leak"
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    async def test_successful_credential_task_logs_no_token(self, mock_plugin_dirs, caplog, capsys):
        """The happy path emits no token to any sink either.

        Reconstruction itself must not log the field it read, and the response
        the worker prints carries only the redacted payload.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.extensions.security import SubjectExtension
        from cpex.framework.hooks.identity import IdentityResolveResult, IdentityResult

        class ResolvingIdentityPlugin(Plugin):
            """Resolves a subject without echoing the token."""

            async def identity_resolve(self, payload, context, extensions=None):
                assert payload.raw_token.get_secret_value() == TestCredentialRedactionHardening.TOKEN
                return IdentityResolveResult(
                    continue_processing=True,
                    modified_payload=IdentityResult(
                        subject=SubjectExtension(id="alice@corp.com", type="user"),
                    ),
                )

        task_data = self._task(mock_plugin_dirs, "cred_plugin.ResolvingIdentityPlugin")

        mock_module = MagicMock()
        mock_module.ResolvingIdentityPlugin = ResolvingIdentityPlugin

        with caplog.at_level(logging.DEBUG):
            with patch("cpex.framework.isolated.worker.import_module", return_value=mock_module):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]
                    await main()

        captured = capsys.readouterr()
        assert self.TOKEN not in captured.out
        assert self.TOKEN not in captured.err
        assert self.TOKEN not in caplog.text
        # The request did succeed — this is not a vacuous pass.
        output = json.loads(captured.out.strip().splitlines()[-1])
        assert output["continue_processing"] is True
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    async def test_oversized_response_error_path_leaks_no_token(self, mock_plugin_dirs, caplog, capsys):
        """The max-content-size rejection path emits no token.

        That path replaces the response wholesale, but it also logs — and it runs
        with a credential-bearing task's result in scope.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.identity import IdentityResolveResult, IdentityResult

        class EchoingIdentityPlugin(Plugin):
            """Returns a result large enough to trip the size guard."""

            async def identity_resolve(self, payload, context, extensions=None):
                return IdentityResolveResult(
                    continue_processing=True,
                    modified_payload=IdentityResult(reject_reason="x" * 500),
                )

        task_data = self._task(mock_plugin_dirs, "cred_plugin.EchoingIdentityPlugin")
        # Force the response over the limit so the rejection branch runs.
        config_dict = {"name": "cred_plugin", "kind": "isolated_venv", "config": {}, "max_content_size": 100}
        task_data["config"] = json.dumps(config_dict)

        mock_module = MagicMock()
        mock_module.EchoingIdentityPlugin = EchoingIdentityPlugin

        with caplog.at_level(logging.DEBUG):
            with patch("cpex.framework.isolated.worker.import_module", return_value=mock_module):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]
                    await main()

        captured = capsys.readouterr()
        assert self.TOKEN not in captured.out
        assert self.TOKEN not in captured.err
        assert self.TOKEN not in caplog.text
        self.cleanup_mock_plugin_dirs()

    @pytest.mark.asyncio
    async def test_plugin_echoing_payload_back_leaks_no_token(self, mock_plugin_dirs, caplog, capsys):
        """A plugin that returns its payload as modified_payload leaks nothing.

        Regression for a real hole: header synthesis originally wrote
        ``{source_header: <plaintext>}`` onto the payload. ``headers`` is
        ``dict[str, str]``, not ``SecretStr``, so it does not redact — and a
        TRANSFORM-mode identity plugin echoing the payload back put that plaintext
        straight onto the stdout channel the host reads, even though ``raw_token``
        itself was correctly redacted.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.hooks.identity import IdentityResolveResult

        class EchoingIdentityPlugin(Plugin):
            """Returns its own (reconstructed) payload back to the framework."""

            async def identity_resolve(self, payload, context, extensions=None):
                assert payload.raw_token.get_secret_value() == TestCredentialRedactionHardening.TOKEN
                return IdentityResolveResult(continue_processing=True, modified_payload=payload)

        task_data = self._task(mock_plugin_dirs, "cred_plugin.EchoingIdentityPlugin")

        mock_module = MagicMock()
        mock_module.EchoingIdentityPlugin = EchoingIdentityPlugin

        with caplog.at_level(logging.DEBUG):
            with patch("cpex.framework.isolated.worker.import_module", return_value=mock_module):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.readline.side_effect = [json.dumps(task_data) + "\n", ""]
                    await main()

        captured = capsys.readouterr()
        assert self.TOKEN not in captured.out, "token leaked to stdout via echoed payload headers"
        assert self.TOKEN not in captured.err
        assert self.TOKEN not in caplog.text
        self.cleanup_mock_plugin_dirs()

    def test_reconstructed_payload_still_redacts_on_serialization(self):
        """The rebuilt payload's secret is a real SecretStr, not a bare string.

        ``model_copy`` bypasses validation, so a plain ``str`` assigned to
        ``raw_token`` would survive construction and then serialize in the clear —
        silently defeating redaction for every downstream consumer.
        """
        from pydantic import SecretStr

        from cpex.framework.hooks.identity import DelegationPayload, IdentityPayload
        from cpex.framework.isolated.worker import reconstruct_credential_payload

        identity = reconstruct_credential_payload(
            "identity_resolve",
            IdentityPayload(raw_token=SecretStr("**********"), source="bearer", headers={}),
            {"inbound": {"token": self.TOKEN, "source_header": "Authorization", "kind": "jwt"}},
        )
        assert isinstance(identity.raw_token, SecretStr)
        assert self.TOKEN not in json.dumps(identity.model_dump(mode="json"))
        assert self.TOKEN not in str(identity)
        assert self.TOKEN not in repr(identity)

        delegation = reconstruct_credential_payload(
            "token_delegate",
            DelegationPayload(target_name="t", bearer_token=SecretStr("**********")),
            {"delegated": {"token": self.TOKEN, "outbound_header": "Authorization"}},
        )
        assert isinstance(delegation.bearer_token, SecretStr)
        assert self.TOKEN not in json.dumps(delegation.model_dump(mode="json"))
        assert self.TOKEN not in str(delegation)
        assert self.TOKEN not in repr(delegation)


class TestScrubbingLogFactory:
    """Unit coverage for the log scrub, at the seams a filter-based one missed.

    Each test here corresponds to a leak that was confirmed reachable against a
    handler-attached ``logging.Filter``: the filter rewrote ``record.msg`` and
    string ``record.args``, which leaves the rendered traceback, every non-string
    argument, and any logger whose records never reach root's handlers.
    """

    TOKEN = "FACTORY-CANARY-abc123xyz"

    @pytest.fixture
    def sink(self):
        """Capture root log output in a buffer, restoring config afterward."""
        import io

        root = logging.getLogger()
        prior_handlers = list(root.handlers)
        prior_level = root.level
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        root.handlers = [handler]
        root.setLevel(logging.DEBUG)
        try:
            yield buffer
        finally:
            root.handlers = prior_handlers
            root.setLevel(prior_level)

    def test_exc_info_traceback_is_scrubbed(self, sink):
        """logger.exception() must not leak the token through the traceback.

        The formatter renders ``exc_info`` separately via ``formatException`` and
        appends it, so scrubbing only the message leaves the traceback — and its
        ``raise ValueError(f"... {token}")`` source line — in the clear. This is
        the *caught*-exception case: nothing propagates, so the exception-text
        scrubber never sees it.
        """
        from cpex.framework.isolated.worker import scrubbing_log_factory

        with scrubbing_log_factory(self.TOKEN):
            try:
                raise ValueError(f"inner {self.TOKEN}")
            except ValueError:
                logging.getLogger("plugin.under.test").exception("hook failed")

        output = sink.getvalue()
        assert self.TOKEN not in output, "token leaked via exc_info traceback"
        # Not a vacuous pass: the traceback really was rendered.
        assert "Traceback" in output
        assert "**********" in output

    @pytest.mark.parametrize(
        "arg",
        [
            pytest.param(ValueError("TOKEN_HERE"), id="exception-object"),
            pytest.param(["TOKEN_HERE"], id="list"),
            pytest.param(b"TOKEN_HERE", id="bytes"),
            pytest.param({"nested": ["TOKEN_HERE"]}, id="nested-dict"),
            pytest.param(("TOKEN_HERE",), id="tuple"),
        ],
    )
    def test_non_string_log_args_are_scrubbed(self, sink, arg):
        """A non-str log arg renders the token at format time, after a filter ran.

        ``logger.error("failed: %s", exc)`` is idiomatic, and any library
        exception whose message embeds the token it was handed leaks through it —
        so this is not a hostile-plugin-only path.
        """
        from cpex.framework.isolated.worker import scrubbing_log_factory

        # Build the arg with the real token (parametrize ids stay readable).
        if isinstance(arg, ValueError):
            arg = ValueError(self.TOKEN)
        elif isinstance(arg, list):
            arg = [self.TOKEN]
        elif isinstance(arg, bytes):
            arg = self.TOKEN.encode()
        elif isinstance(arg, dict):
            arg = {"nested": [self.TOKEN]}
        elif isinstance(arg, tuple):
            arg = (self.TOKEN,)

        with scrubbing_log_factory(self.TOKEN):
            logging.getLogger("plugin.under.test").error("value: %s", arg)

        assert self.TOKEN not in sink.getvalue()

    def test_dict_style_log_args_are_scrubbed(self, sink):
        """%(name)s-style dict args are scrubbed too, including nested values."""
        from cpex.framework.isolated.worker import scrubbing_log_factory

        with scrubbing_log_factory(self.TOKEN):
            logging.getLogger("plugin.under.test").error(
                "tok=%(tok)s nested=%(nested)s", {"tok": self.TOKEN, "nested": [self.TOKEN]}
            )

        assert self.TOKEN not in sink.getvalue()

    def test_logger_with_propagate_false_is_scrubbed(self):
        """A logger with propagate=False and its own handler bypasses root.

        Mainstream library configuration — many SDKs set it to avoid
        double-logging — so a plugin inherits this gap just by importing one.
        """
        import io

        from cpex.framework.isolated.worker import scrubbing_log_factory

        buffer = io.StringIO()
        isolated = logging.getLogger("plugin.isolated.noprop")
        prior_handlers, prior_propagate = list(isolated.handlers), isolated.propagate
        isolated.handlers = [logging.StreamHandler(buffer)]
        isolated.propagate = False
        isolated.setLevel(logging.DEBUG)
        try:
            with scrubbing_log_factory(self.TOKEN):
                isolated.error("noprop: %s", self.TOKEN)
        finally:
            isolated.handlers, isolated.propagate = prior_handlers, prior_propagate

        assert self.TOKEN not in buffer.getvalue()

    def test_scrubbed_with_zero_root_handlers(self, capsys):
        """With no root handlers, logging.lastResort emits to stderr carrying no filters.

        A handler-attached filter has nothing to attach to in this state, so the
        executor's "Plugin %s failed with error: %s" line went out verbatim.
        """
        from cpex.framework.isolated.worker import scrubbing_log_factory

        root = logging.getLogger()
        prior_handlers, prior_level = list(root.handlers), root.level
        root.handlers = []
        try:
            with scrubbing_log_factory(self.TOKEN):
                logging.getLogger("cpex.framework.manager").error("Plugin p failed: %s", self.TOKEN)
        finally:
            root.handlers, root.level = prior_handlers, prior_level

        captured = capsys.readouterr()
        assert self.TOKEN not in captured.err
        assert self.TOKEN not in captured.out

    def test_handler_added_during_the_call_is_scrubbed(self, sink):
        """A handler installed mid-call still sees scrubbed records.

        Scrubbing at record *creation* is what makes this hold: the record is
        already rewritten before any handler — pre-existing or not — is consulted.
        """
        import io

        from cpex.framework.isolated.worker import scrubbing_log_factory

        late_buffer = io.StringIO()
        root = logging.getLogger()
        with scrubbing_log_factory(self.TOKEN):
            root.handlers = [logging.StreamHandler(late_buffer)]
            logging.getLogger("plugin.under.test").error("late: %s", self.TOKEN)

        assert self.TOKEN not in late_buffer.getvalue()

    def test_factory_is_restored_and_later_tasks_unaffected(self, sink):
        """The scrub does not outlive its context, nor retain the token after it."""
        from cpex.framework.isolated.worker import scrubbing_log_factory

        original_factory = logging.getLogRecordFactory()
        with scrubbing_log_factory(self.TOKEN):
            assert logging.getLogRecordFactory() is not original_factory
        assert logging.getLogRecordFactory() is original_factory

        # A later, unrelated task's log output is untouched by the prior token.
        logging.getLogger("plugin.under.test").error("later task: %s", self.TOKEN)
        assert self.TOKEN in sink.getvalue(), "scrub leaked into a later task"

    def test_nested_contexts_restore_in_order(self, sink):
        """Nested scrubs compose and unwind cleanly, both tokens covered."""
        from cpex.framework.isolated.worker import scrubbing_log_factory

        outer_token, inner_token = "OUTER-CANARY-1", "INNER-CANARY-2"
        baseline = logging.getLogRecordFactory()
        with scrubbing_log_factory(outer_token):
            with scrubbing_log_factory(inner_token):
                logging.getLogger("plugin.under.test").error("%s and %s", outer_token, inner_token)
            assert logging.getLogRecordFactory() is not baseline
        assert logging.getLogRecordFactory() is baseline

        output = sink.getvalue()
        assert outer_token not in output
        assert inner_token not in output


class TestHeaderScrubbing:
    """``headers`` is dict[str, str] and does NOT redact on serialization.

    ``model_copy(update=...)`` skips validation, so an off-type value survives onto
    the model and reaches stdout via any plugin that copies ``payload.headers``
    into ``IdentityResult.raw_claims`` for audit.
    """

    TOKEN = "HEADER-CANARY-abc123"

    @pytest.mark.parametrize(
        "headers_in",
        [
            pytest.param({"Authorization": "TOKEN"}, id="plain-string-value"),
            pytest.param({"Authorization": "Bearer TOKEN"}, id="embedded-in-value"),
            pytest.param({"Authorization": ["Bearer TOKEN"]}, id="list-value"),
            pytest.param({"Authorization": {"inner": "TOKEN"}}, id="nested-dict-value"),
            pytest.param({"Authorization": [{"deep": ["TOKEN"]}]}, id="deeply-nested-value"),
            pytest.param({"X-TOKEN": "v"}, id="token-in-key"),
            pytest.param({"A": "TOKEN", "B": ["TOKEN"], "C": "safe"}, id="mixed"),
        ],
    )
    def test_no_shape_of_header_carries_the_plaintext(self, headers_in):
        """No JSON shape — nested, keyed, or off-type — smuggles the token through."""
        from cpex.framework.isolated.worker import _scrub_token_from_headers

        headers = json.loads(json.dumps(headers_in).replace("TOKEN", self.TOKEN))
        scrubbed = _scrub_token_from_headers(headers, self.TOKEN)

        assert self.TOKEN not in json.dumps(scrubbed)
        # Coerced to the declared dict[str, str] so model_copy cannot smuggle a
        # container onto the validated field.
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in scrubbed.items())

    def test_unrelated_headers_survive_untouched(self):
        """Scrubbing is surgical: headers not carrying the token are preserved."""
        from cpex.framework.isolated.worker import _scrub_token_from_headers

        scrubbed = _scrub_token_from_headers({"X-Trace": "abc", "X-Request-Id": "42"}, self.TOKEN)
        assert scrubbed == {"X-Trace": "abc", "X-Request-Id": "42"}

    def test_off_type_header_value_never_reaches_the_payload(self):
        """End of the chain: a list-valued header cannot land on the model."""
        from pydantic import SecretStr

        from cpex.framework.hooks.identity import IdentityPayload
        from cpex.framework.isolated.worker import reconstruct_credential_payload

        rebuilt = reconstruct_credential_payload(
            "identity_resolve",
            IdentityPayload(raw_token=SecretStr("**********"), source="bearer", headers={}),
            {
                "inbound": {
                    "token": self.TOKEN,
                    "source_header": "Authorization",
                    "headers": {"Authorization": [f"Bearer {self.TOKEN}"]},
                }
            },
        )

        assert self.TOKEN not in json.dumps(rebuilt.model_dump(mode="json"))
        assert all(isinstance(v, str) for v in rebuilt.headers.values())
        # The plaintext still reaches the hook, on the field that redacts.
        assert rebuilt.raw_token.get_secret_value() == self.TOKEN

    def test_token_bearing_source_header_is_scrubbed_from_the_key(self):
        """A source_header embedding the token cannot put it in a dict key."""
        from pydantic import SecretStr

        from cpex.framework.hooks.identity import IdentityPayload
        from cpex.framework.isolated.worker import reconstruct_credential_payload

        rebuilt = reconstruct_credential_payload(
            "identity_resolve",
            IdentityPayload(raw_token=SecretStr("**********"), source="bearer", headers={}),
            {"inbound": {"token": self.TOKEN, "source_header": f"X-{self.TOKEN}"}},
        )

        assert self.TOKEN not in json.dumps(rebuilt.model_dump(mode="json"))


class TestCredentialFailClosedHardening:
    """Fail-closed gaps found by security review."""

    @pytest.mark.parametrize(
        "token",
        [
            pytest.param("   ", id="spaces"),
            pytest.param("\t", id="tab"),
            pytest.param("\n", id="newline"),
            pytest.param(" \t\n ", id="mixed-whitespace"),
        ],
    )
    def test_whitespace_only_token_is_rejected(self, token):
        """A whitespace-only token is a truthy str but an empty bearer downstream.

        ``Authorization: Bearer    `` is not meaningfully different from
        ``Bearer `` to a verifier, and a plugin that strips before use ends up
        with exactly the empty string the guard exists to prevent.
        """
        from cpex.framework.isolated.worker import CredentialError, _extract_credential_token

        with pytest.raises(CredentialError, match="missing or empty"):
            _extract_credential_token({"inbound": {"token": token}}, "inbound")

    def test_payload_type_mismatch_fails_closed(self):
        """A hook_type/payload mismatch raises instead of silently failing open.

        ``model_copy`` does not validate, so writing ``raw_token`` onto a
        ``DelegationPayload`` used to succeed — leaving a stray attribute while
        ``bearer_token`` (what the hook reads) kept its redacted placeholder. The
        credential silently did not arrive, and no error was raised.
        """
        from pydantic import SecretStr

        from cpex.framework.hooks.identity import DelegationPayload, IdentityPayload
        from cpex.framework.isolated.worker import CredentialError, reconstruct_credential_payload

        with pytest.raises(CredentialError, match="does not match hook"):
            reconstruct_credential_payload(
                "identity_resolve",
                DelegationPayload(target_name="t", bearer_token=SecretStr("**********")),
                {"inbound": {"token": "REALTOKEN"}},
            )

        with pytest.raises(CredentialError, match="does not match hook"):
            reconstruct_credential_payload(
                "token_delegate",
                IdentityPayload(raw_token=SecretStr("**********")),
                {"delegated": {"token": "REALTOKEN"}},
            )

    def test_type_mismatch_error_names_no_credential_value(self):
        """The mismatch error names types only, never the token."""
        from pydantic import SecretStr

        from cpex.framework.hooks.identity import DelegationPayload
        from cpex.framework.isolated.worker import CredentialError, reconstruct_credential_payload

        try:
            reconstruct_credential_payload(
                "identity_resolve",
                DelegationPayload(target_name="t", bearer_token=SecretStr("**********")),
                {"inbound": {"token": "SECRET-VALUE-XYZ"}},
            )
            raise AssertionError("expected CredentialError")
        except CredentialError as ce:
            assert "SECRET-VALUE-XYZ" not in str(ce)


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
        assert output_data["request_id"] == "req-789"

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

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_error_uses_current_request_id_not_stale(
        self, mock_process_task, mock_print, mock_stdin
    ):
        """An error on task B must carry B's request_id, never a stale A id.

        Regression: request_id was a main()-local reused across loop iterations,
        so an error emitted before/without re-setting it could carry the prior
        request's id. venv_comm demuxes strictly on request_id, so a stale id
        misdelivers the error or hangs the real caller until timeout.
        """
        task_a = {"task_type": "info", "request_id": "req-A"}
        task_b = {"task_type": "info", "request_id": "req-B"}
        mock_stdin.readline.side_effect = [
            json.dumps(task_a) + "\n",
            json.dumps(task_b) + "\n",
            "",  # EOF
        ]

        ok = MagicMock()
        ok.model_dump.return_value = {"status": "success"}
        # First task succeeds; second raises before a response is built.
        mock_process_task.side_effect = [ok, RuntimeError("boom on B")]

        await main()

        # Second print is the error response for task B.
        error_output = json.loads(mock_print.call_args_list[1][0][0])
        assert error_output["status"] == "error"
        assert error_output["request_id"] == "req-B"

    @pytest.mark.asyncio
    @patch("sys.stdin")
    @patch("builtins.print")
    @patch("cpex.framework.isolated.worker.process_task")
    async def test_main_error_before_parse_reports_unknown(
        self, mock_process_task, mock_print, mock_stdin
    ):
        """A malformed line after a good task reports "unknown", not the prior id.

        The prior task set request_id to a real value; the per-iteration reset
        ensures a subsequent JSON decode error does not inherit it.
        """
        task_a = {"task_type": "info", "request_id": "req-A"}
        mock_stdin.readline.side_effect = [
            json.dumps(task_a) + "\n",
            "not-json\n",
            "",  # EOF
        ]

        ok = MagicMock()
        ok.model_dump.return_value = {"status": "success"}
        mock_process_task.return_value = ok

        await main()

        error_output = json.loads(mock_print.call_args_list[1][0][0])
        assert error_output["status"] == "error"
        assert error_output["request_id"] == "unknown"


class TestExtensionsDelivery:
    """The ``extensions`` task field reaching a 3-arg hook, and coming back.

    Before this, ``process_task`` called ``execute_plugin`` with no
    ``extensions`` argument, so every out-of-process hook saw ``extensions=None``
    — a plugin using the 3-arg ``(payload, context, extensions)`` signature lost
    all extension context that its in-process equivalent receives.

    The wire contract is shared with the Rust host and pinned in
    ``docs/specs/extensions-wire-contract.md``: ``extensions`` inbound on the
    task, ``modified_extensions`` outbound on the response (the field the
    ``PluginResult`` model already carries), sensitive headers stripped in both
    directions, and no ``raw_credentials`` slot on this channel at all.
    """

    @pytest.fixture
    def mock_plugin_dirs(self):
        """Ensure the plugins directory exists."""
        plugin_dirs = Path(os.getcwd()) / "tmp" / "plugins"
        plugin_dirs.mkdir(parents=True, exist_ok=True)
        return [str(plugin_dirs.resolve())]

    @staticmethod
    def _task(mock_plugin_dirs, extensions=None, class_name="ext_plugin.RecordingPlugin", capabilities=None):
        """Build a tool_pre_invoke task, optionally carrying an extensions field."""
        config_dict = {"name": "ext_plugin", "kind": "isolated_venv", "config": {}}
        if capabilities is not None:
            config_dict["capabilities"] = capabilities
        task_data = {
            "task_type": "load_and_run_hook",
            "config": json.dumps(config_dict),
            "plugin_dirs": mock_plugin_dirs,
            "class_name": class_name,
            "hook_type": "tool_pre_invoke",
            "payload": {"name": "search", "args": {"q": "hello"}},
            "context": {"state": {}, "global_context": {"request_id": "req-ext"}, "metadata": {}},
        }
        if extensions is not None:
            task_data["extensions"] = extensions
        return task_data

    @staticmethod
    def _wire_extensions():
        """An inbound wire dict shaped as the Rust host sends it.

        Sensitive headers are absent because the host strips them before the task
        is written; what arrives is the already-scrubbed view.
        """
        return {
            "security": {"labels": ["PII"], "classification": "confidential"},
            "agent": {"agent_id": "agent-7"},
            # The Python HttpExtension carries a single `headers` dict; the Rust
            # one splits request/response. See the http-slot note in
            # docs/specs/extensions-wire-contract.md.
            "http": {"headers": {"X-Request-Id": "req-ext-1"}},
            "custom": {"trace": True},
        }

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_three_arg_hook_receives_reconstructed_extensions(self, mock_import, mock_plugin_dirs):
        """A task with an extensions field delivers a populated Extensions to a 3-arg hook."""
        from cpex.framework.base import Plugin
        from cpex.framework.extensions.extensions import Extensions
        from cpex.framework.models import PluginResult

        received = {}

        class RecordingPlugin(Plugin):
            """Records the extensions object the framework handed the hook."""

            async def tool_pre_invoke(self, payload, context, extensions):
                received["type"] = type(extensions)
                received["labels"] = sorted(extensions.security.labels) if extensions.security else None
                received["classification"] = extensions.security.classification if extensions.security else None
                received["agent_id"] = extensions.agent.agent_id if extensions.agent else None
                received["custom"] = dict(extensions.custom) if extensions.custom else None
                return PluginResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.RecordingPlugin = RecordingPlugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            extensions=self._wire_extensions(),
            # read_labels/read_agent so the framework's own filter keeps the slots
            # visible; the host already filtered, this must not re-hide them.
            capabilities=["read_labels", "read_agent", "read_headers"],
        )
        result = await process_task(task_data, TaskProcessor())

        assert result is not None
        assert result.continue_processing is True
        assert received["type"] is Extensions, "the hook must receive a real Extensions, not a dict"
        assert received["labels"] == ["PII"]
        assert received["classification"] == "confidential"
        assert received["agent_id"] == "agent-7"
        assert received["custom"] == {"trace": True}

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_two_arg_hook_runs_without_extensions(self, mock_import, mock_plugin_dirs):
        """A 2-arg hook still runs when the task carries extensions, and sees none.

        The framework withholds extensions from 2-arg hooks; the worker must not
        force the argument and break every existing plugin.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        calls = []

        class RecordingPlugin(Plugin):
            """A pre-existing 2-arg plugin shape."""

            async def tool_pre_invoke(self, payload, context):
                calls.append(payload.name)
                return PluginResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.RecordingPlugin = RecordingPlugin
        mock_import.return_value = mock_module

        task_data = self._task(mock_plugin_dirs, extensions=self._wire_extensions())
        result = await process_task(task_data, TaskProcessor())

        assert result is not None
        assert result.continue_processing is True
        assert calls == ["search"], "the 2-arg hook must still be invoked, with no extensions"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_absent_extensions_field_yields_none(self, mock_import, mock_plugin_dirs):
        """No extensions field means the hook sees None — today's behavior, unchanged."""
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        received = {}

        class RecordingPlugin(Plugin):
            """Records that extensions were absent."""

            async def tool_pre_invoke(self, payload, context, extensions):
                received["extensions"] = extensions
                return PluginResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.RecordingPlugin = RecordingPlugin
        mock_import.return_value = mock_module

        task_data = self._task(mock_plugin_dirs)  # no extensions field
        result = await process_task(task_data, TaskProcessor())

        assert result is not None
        assert received["extensions"] is None

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_reconstruction_of_frozen_extensions_succeeds(self, mock_import, mock_plugin_dirs):
        """A frozen model still constructs from a dict — frozen blocks mutation, not construction.

        Guards the plan's stated risk directly: if ``frozen=True`` were mistaken
        for "cannot be built from a dict", the whole channel would be assumed
        impossible.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        received = {}

        class RecordingPlugin(Plugin):
            """Confirms the object is frozen yet was constructed."""

            async def tool_pre_invoke(self, payload, context, extensions):
                received["built"] = extensions is not None
                try:
                    extensions.custom = {"mutated": True}
                    received["frozen"] = False
                except Exception:
                    received["frozen"] = True
                return PluginResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.RecordingPlugin = RecordingPlugin
        mock_import.return_value = mock_module

        task_data = self._task(mock_plugin_dirs, extensions=self._wire_extensions())
        await process_task(task_data, TaskProcessor())

        assert received["built"] is True
        assert received["frozen"] is True, "Extensions must remain frozen after reconstruction"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_unknown_slot_does_not_break_reconstruction(self, mock_import, mock_plugin_dirs):
        """A slot this Python version does not model must not fail the task.

        The two surfaces version independently. A host that grows a slot ahead of
        the worker would otherwise take every plugin down at reconstruction.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        received = {}

        class RecordingPlugin(Plugin):
            """Records that the known slots survived an unknown one."""

            async def tool_pre_invoke(self, payload, context, extensions):
                received["labels"] = sorted(extensions.security.labels) if extensions.security else None
                return PluginResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.RecordingPlugin = RecordingPlugin
        mock_import.return_value = mock_module

        wire = self._wire_extensions()
        wire["some_future_slot"] = {"whatever": 1}
        task_data = self._task(mock_plugin_dirs, extensions=wire, capabilities=["read_labels"])
        result = await process_task(task_data, TaskProcessor())

        assert result is not None, "an unknown slot must not fail the task"
        assert received["labels"] == ["PII"]

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_appended_label_returns_on_modified_extensions(self, mock_import, mock_plugin_dirs):
        """A plugin that appends a label returns it on modified_extensions."""
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        class AppendingPlugin(Plugin):
            """Appends a security label via model_copy, since Extensions is frozen."""

            async def tool_pre_invoke(self, payload, context, extensions):
                new_security = extensions.security.model_copy(
                    update={"labels": sorted(set(extensions.security.labels) | {"SCANNED"})}
                )
                return PluginResult(
                    continue_processing=True,
                    modified_extensions=extensions.model_copy(update={"security": new_security}),
                )

        mock_module = MagicMock()
        mock_module.AppendingPlugin = AppendingPlugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            extensions=self._wire_extensions(),
            class_name="ext_plugin.AppendingPlugin",
            capabilities=["read_labels", "append_labels"],
        )
        result = await process_task(task_data, TaskProcessor())

        assert result.modified_extensions is not None, "the plugin's extensions must ride back"
        labels = sorted(result.modified_extensions.security.labels)
        assert "SCANNED" in labels, "the appended label must survive into the response"
        assert "PII" in labels, "and the inbound label must still be there"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_untouched_extensions_report_no_change(self, mock_import, mock_plugin_dirs):
        """A plugin that ignores extensions leaves modified_extensions unset.

        Omission is the contract's "no change" sentinel: the Rust merge validates
        the immutable tier by pointer identity, so an echo could not be
        distinguished from tampering.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        class PassivePlugin(Plugin):
            """Reads extensions but returns none."""

            async def tool_pre_invoke(self, payload, context, extensions):
                return PluginResult(continue_processing=True)

        mock_module = MagicMock()
        mock_module.PassivePlugin = PassivePlugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            extensions=self._wire_extensions(),
            class_name="ext_plugin.PassivePlugin",
        )
        result = await process_task(task_data, TaskProcessor())

        assert result.modified_extensions is None, "no modification must serialize as no field"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_returned_sensitive_headers_are_stripped(self, mock_import, mock_plugin_dirs):
        """A plugin cannot ship a credential header back to the host.

        Stripping must be symmetric. The host scrubs on the way out; if the
        worker did not scrub on the way back, a plugin could inject
        ``Authorization`` into the pipeline through its return value — reaching
        the very channel the credential path exists to keep it off of.
        """
        from cpex.framework.base import Plugin
        from cpex.framework.extensions.http import HttpExtension
        from cpex.framework.models import PluginResult

        class InjectingPlugin(Plugin):
            """Returns extensions carrying sensitive headers."""

            async def tool_pre_invoke(self, payload, context, extensions):
                http = HttpExtension(
                    headers={
                        "Authorization": "Bearer injected",
                        "cookie": "session=injected",
                        "X-API-Key": "injected",
                        "Set-Cookie": "s=injected",
                        "X-Fine": "yes",
                        "Content-Type": "application/json",
                    },
                )
                return PluginResult(
                    continue_processing=True,
                    modified_extensions=extensions.model_copy(update={"http": http}),
                )

        mock_module = MagicMock()
        mock_module.InjectingPlugin = InjectingPlugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            extensions=self._wire_extensions(),
            class_name="ext_plugin.InjectingPlugin",
            capabilities=["read_headers", "write_headers"],
        )
        result = await process_task(task_data, TaskProcessor())

        http = result.modified_extensions.http
        names = {k.lower() for k in http.headers}
        assert "authorization" not in names, "Authorization must not ride back"
        assert "cookie" not in names, "Cookie must not ride back (matched case-insensitively)"
        assert "x-api-key" not in names, "X-API-Key must not ride back"
        assert http.headers.get("X-Fine") == "yes", "a benign header still returns"
        assert http.headers.get("Content-Type") == "application/json"

        # The response is what main() serializes to the stdout channel the host
        # reads, so assert on the serialized form rather than just the model. Only
        # the three spec'd names are stripped, so scope the leak check to those —
        # `Set-Cookie` is deliberately not on that list.
        serialized = json.dumps(result.model_dump(mode="json"), default=str)
        assert "Bearer injected" not in serialized, f"no bearer token may reach the wire: {serialized}"
        assert "session=injected" not in serialized, f"no cookie may reach the wire: {serialized}"

    @pytest.mark.asyncio
    @patch("cpex.framework.isolated.worker.import_module")
    async def test_custom_change_returns_intact(self, mock_import, mock_plugin_dirs):
        """The mutable slot round-trips as-is — the common case for plugin output."""
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginResult

        class CustomPlugin(Plugin):
            """Writes a verdict into the mutable custom slot."""

            async def tool_pre_invoke(self, payload, context, extensions):
                return PluginResult(
                    continue_processing=True,
                    modified_extensions=extensions.model_copy(update={"custom": {"verdict": "clean", "score": 3}}),
                )

        mock_module = MagicMock()
        mock_module.CustomPlugin = CustomPlugin
        mock_import.return_value = mock_module

        task_data = self._task(
            mock_plugin_dirs,
            extensions=self._wire_extensions(),
            class_name="ext_plugin.CustomPlugin",
        )
        result = await process_task(task_data, TaskProcessor())

        assert result.modified_extensions.custom == {"verdict": "clean", "score": 3}


# Made with Bob
