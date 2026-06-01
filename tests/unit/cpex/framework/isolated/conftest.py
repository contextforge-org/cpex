# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/isolated/conftest.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Pytest fixtures for isolated plugin tests.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cpex.framework import GlobalContext
from cpex.framework.models import PluginConfig, PluginContext


@pytest.fixture
def mock_venv_structure(tmp_path):
    """Create a mock virtual environment directory structure.
    
    Args:
        tmp_path: pytest tmp_path fixture
        
    Returns:
        Path to the mock venv directory
    """
    venv_path = tmp_path / ".venv"
    venv_path.mkdir()
    
    # Create appropriate bin/Scripts directory based on platform
    if sys.platform == "win32":
        scripts_dir = venv_path / "Scripts"
        scripts_dir.mkdir()
        python_exe = scripts_dir / "python.exe"
    else:
        bin_dir = venv_path / "bin"
        bin_dir.mkdir()
        python_exe = bin_dir / "python"
    
    # Create a dummy python executable
    python_exe.touch()
    python_exe.chmod(0o755)
    
    return venv_path


@pytest.fixture
def sample_plugin_config(tmp_path):
    """Create a sample plugin configuration for testing.
    
    Args:
        tmp_path: pytest tmp_path fixture
        
    Returns:
        PluginConfig instance
    """
    venv_path = tmp_path / ".venv"
    script_path = tmp_path / "plugin"
    requirements_file = tmp_path / "requirements.txt"
    
    config_dict = {
        "name": "test_isolated_plugin",
        "kind": "isolated_venv",
        "description": "Test isolated plugin",
        "version": "1.0.0",
        "author": "Test Author",
        "hooks": ["tool_pre_invoke", "tool_post_invoke"],
        "config": {
            "venv_path": str(venv_path),
            "script_path": str(script_path),
            "requirements_file": str(requirements_file),
            "class_name": "test_plugin.TestPlugin"
        }
    }
    return PluginConfig(**config_dict)


@pytest.fixture
def sample_global_context():
    """Create a sample GlobalContext for testing.
    
    Returns:
        GlobalContext instance
    """
    return GlobalContext(
        request_id="test-req-123",
        user="test_user",
        tenant_id="test-tenant",
        server_id="test-server"
    )


@pytest.fixture
def sample_plugin_context(sample_global_context):
    """Create a sample PluginContext for testing.
    
    Args:
        sample_global_context: GlobalContext fixture
        
    Returns:
        PluginContext instance
    """
    return PluginContext(
        global_context=sample_global_context,
        state={"test_key": "test_value"},
        metadata={"test_meta": "test_data"}
    )


@pytest.fixture
def mock_communicator():
    """Create a mock VenvProcessCommunicator.
    
    Returns:
        MagicMock instance configured as a communicator
    """
    mock_comm = MagicMock()
    mock_comm.install_requirements = MagicMock()
    mock_comm.send_task = MagicMock(return_value={
        "continue_processing": True,
        "modified_payload": None,
        "violation": None,
        "metadata": {}
    })
    return mock_comm


@pytest.fixture
def sample_requirements_file(tmp_path):
    """Create a sample requirements.txt file.
    
    Args:
        tmp_path: pytest tmp_path fixture
        
    Returns:
        Path to the requirements file
    """
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("pytest>=7.0.0\nrequests>=2.28.0\n")
    return requirements_file

# Made with Bob
