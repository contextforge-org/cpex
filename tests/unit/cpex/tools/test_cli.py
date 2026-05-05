# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/tools/test_cli.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Tests for the cpex CLI bootstrap command and utility functions.
"""

# Standard
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest
# We use typer's CliRunner for testing typer apps
import click
from typer.testing import CliRunner

# Third-Party
# First-Party
from cpex.tools.cli import (
    DEFAULT_AUTHOR_EMAIL,
    DEFAULT_AUTHOR_NAME,
    DEFAULT_TEMPLATE_URL,
    LOCAL_TEMPLATES_DIR,
    app,
    command_exists,
    git_user_email,
    git_user_name,
    list_registered_plugins,
    install_from_manifest,
    install,
    search,
    info,
    instance_name_is_unique,
    update_plugins_config_yaml,
    remove_from_plugins_config_yaml,
    uninstall,
)
from cpex.tools.plugin_registry import PluginRegistry
from cpex.framework.models import PluginManifest, Monorepo, Config, PluginConfig, PluginMode, PyPiRepo

runner = CliRunner()

# cookiecutter is imported locally inside bootstrap(); patch at source module
_CC_PATCH_TARGET = "cookiecutter.main.cookiecutter"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_registry_dir(tmp_path, monkeypatch):
    """Fixture to ensure all tests use a temporary directory for the plugin registry."""
    registry_dir = tmp_path / "test_registry"
    registry_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("PLUGIN_REGISTRY_FILE", str(registry_dir))
    return registry_dir


# Helper function to create test manifests
def create_test_manifest(**kwargs):
    """Create a test PluginManifest with default values."""
    defaults = {
        "name": "test_plugin",
        "version": "1.0.0",
        "kind": "native",
        "description": "Test plugin description",
        "author": "Test Author",
        "tags": ["test"],
        "available_hooks": ["tools"],
        "default_config": {},
        "monorepo": Monorepo(package_source="https://example.com/repo#subdirectory=plugin", repo_url="https://example.com/repo", package_folder="plugin"),
    }
    defaults.update(kwargs)
    return PluginManifest(**defaults)


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------


class TestCommandExists:
    """Tests for command_exists utility."""

    def test_existing_command(self):
        assert command_exists("python") is True

    def test_nonexistent_command(self):
        assert command_exists("definitely_not_a_real_command_xyz") is False

    def test_delegates_to_shutil_which(self):
        with patch("cpex.tools.cli.shutil.which", return_value="/usr/bin/git") as mock_which:
            assert command_exists("git") is True
            mock_which.assert_called_once_with("git")

    def test_returns_false_when_shutil_which_returns_none(self):
        with patch("cpex.tools.cli.shutil.which", return_value=None) as mock_which:
            assert command_exists("missing") is False
            mock_which.assert_called_once_with("missing")


class TestGitUserName:
    """Tests for git_user_name utility."""

    def test_returns_string(self):
        result = git_user_name()
        assert isinstance(result, str)

    def test_returns_name_on_success(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"  Test User  "
        with patch("cpex.tools.cli.subprocess.run", return_value=mock_result):
            assert git_user_name() == "Test User"

    def test_returns_default_on_nonzero_returncode(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        with patch("cpex.tools.cli.subprocess.run", return_value=mock_result):
            assert git_user_name() == DEFAULT_AUTHOR_NAME

    def test_returns_default_on_exception(self):
        with patch("cpex.tools.cli.subprocess.run", side_effect=FileNotFoundError):
            assert git_user_name() == DEFAULT_AUTHOR_NAME


class TestGitUserEmail:
    """Tests for git_user_email utility."""

    def test_returns_string(self):
        result = git_user_email()
        assert isinstance(result, str)

    def test_returns_email_on_success(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"  test@example.com  "
        with patch("cpex.tools.cli.subprocess.run", return_value=mock_result):
            assert git_user_email() == "test@example.com"

    def test_returns_default_on_nonzero_returncode(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        with patch("cpex.tools.cli.subprocess.run", return_value=mock_result):
            assert git_user_email() == DEFAULT_AUTHOR_EMAIL

    def test_returns_default_on_exception(self):
        with patch("cpex.tools.cli.subprocess.run", side_effect=OSError):
            assert git_user_email() == DEFAULT_AUTHOR_EMAIL


# ---------------------------------------------------------------------------
# Bootstrap command tests
# ---------------------------------------------------------------------------


class TestBootstrapHelp:
    """Test CLI help output."""

    def test_help_exits_zero(self):
        result = runner.invoke(app, ["bootstrap", "--help"])
        assert result.exit_code == 0

    def test_help_contains_options(self):
        result = runner.invoke(app, ["bootstrap", "--help"])
        output = click.unstyle(result.output)
        assert "--destination" in output
        assert "--template_type" in output
        assert "--template_url" in output
        assert "--vcs_ref" in output
        assert "--no_input" in output
        assert "--dry_run" in output


class TestBootstrapDryRun:
    """Test bootstrap --dry_run mode."""

    def test_dry_run_does_not_call_cookiecutter(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            result = runner.invoke(app, ["bootstrap", "--dry_run"])
            assert result.exit_code == 0
            mock_cc.assert_not_called()


class TestBootstrapCookiecutterMissing:
    """Test bootstrap when cookiecutter is not installed."""

    def test_exits_with_code_1_when_cookiecutter_missing(self):
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "cookiecutter.main":
                raise ImportError("mocked: no cookiecutter")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = runner.invoke(app, ["bootstrap", "-d", "/tmp/test_no_cc", "--no_input"])
            assert result.exit_code == 1


class TestBootstrapLocalTemplate:
    """Test bootstrap using local bundled templates."""

    def test_local_templates_dir_exists(self):
        assert LOCAL_TEMPLATES_DIR.is_dir(), f"Expected templates dir at {LOCAL_TEMPLATES_DIR}"

    def test_native_template_exists(self):
        assert (LOCAL_TEMPLATES_DIR / "native").is_dir()

    def test_external_template_exists(self):
        assert (LOCAL_TEMPLATES_DIR / "external").is_dir()

    def test_native_template_has_cookiecutter_json(self):
        assert (LOCAL_TEMPLATES_DIR / "native" / "cookiecutter.json").is_file()

    def test_external_template_has_cookiecutter_json(self):
        assert (LOCAL_TEMPLATES_DIR / "external" / "cookiecutter.json").is_file()

    def test_bootstrap_native_calls_cookiecutter_with_local_path(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            result = runner.invoke(app, ["bootstrap", "-d", "/tmp/test_native", "-t", "native", "--no_input"])
            assert result.exit_code == 0
            mock_cc.assert_called_once()
            call_kwargs = mock_cc.call_args
            # Should use local template path, not remote URL
            template_arg = call_kwargs.kwargs.get("template") or call_kwargs[1].get("template")
            if template_arg is None:
                template_arg = call_kwargs[0][0] if call_kwargs[0] else None
            assert template_arg is not None
            assert "native" in template_arg
            assert "http" not in template_arg

    def test_bootstrap_external_calls_cookiecutter_with_local_path(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            result = runner.invoke(app, ["bootstrap", "-d", "/tmp/test_ext", "-t", "external", "--no_input"])
            assert result.exit_code == 0
            mock_cc.assert_called_once()
            call_kwargs = mock_cc.call_args
            template_arg = call_kwargs.kwargs.get("template") or call_kwargs[1].get("template")
            if template_arg is None:
                template_arg = call_kwargs[0][0] if call_kwargs[0] else None
            assert template_arg is not None
            assert "external" in template_arg
            assert "http" not in template_arg

    def test_bootstrap_passes_no_input_flag(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            runner.invoke(app, ["bootstrap", "-d", "/tmp/test_ni", "--no_input"])
            mock_cc.assert_called_once()
            assert mock_cc.call_args.kwargs["no_input"] is True

    def test_bootstrap_passes_output_dir(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            runner.invoke(app, ["bootstrap", "-d", "/tmp/mydir/my_plugin", "--no_input"])
            mock_cc.assert_called_once()
            assert mock_cc.call_args.kwargs["output_dir"] == "/tmp/mydir"

    def test_bootstrap_passes_extra_context_with_plugin_slug(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            runner.invoke(app, ["bootstrap", "-d", "/tmp/my_plugin", "--no_input"])
            mock_cc.assert_called_once()
            extra = mock_cc.call_args.kwargs["extra_context"]
            assert extra["plugin_slug"] == "my_plugin"

    def test_bootstrap_default_destination_uses_dot_output_dir(self):
        with patch(_CC_PATCH_TARGET) as mock_cc:
            runner.invoke(app, ["bootstrap", "--no_input"])
            mock_cc.assert_called_once()
            assert mock_cc.call_args.kwargs["output_dir"] == "."


class TestBootstrapExplicitUrl:
    """Test bootstrap with explicit --template_url overrides local templates."""

    def test_explicit_url_overrides_local_templates(self):
        with (
            patch("cpex.tools.cli.command_exists", return_value=True),
            patch(_CC_PATCH_TARGET) as mock_cc,
        ):
            result = runner.invoke(
                app,
                [
                    "bootstrap",
                    "-d",
                    "/tmp/test_url",
                    "-u",
                    "https://example.com/repo.git",
                    "--no_input",
                ],
            )
            assert result.exit_code == 0
            mock_cc.assert_called_once()
            assert mock_cc.call_args.kwargs["template"] == "https://example.com/repo.git"
            assert mock_cc.call_args.kwargs["checkout"] == "main"

    def test_explicit_url_with_custom_vcs_ref(self):
        with (
            patch("cpex.tools.cli.command_exists", return_value=True),
            patch(_CC_PATCH_TARGET) as mock_cc,
        ):
            result = runner.invoke(
                app,
                [
                    "bootstrap",
                    "-d",
                    "/tmp/test_url_ref",
                    "-u",
                    "https://example.com/repo.git",
                    "--vcs_ref",
                    "v2.0",
                    "--no_input",
                ],
            )
            assert result.exit_code == 0
            assert mock_cc.call_args.kwargs["checkout"] == "v2.0"

    def test_explicit_url_with_external_template_type(self):
        with (
            patch("cpex.tools.cli.command_exists", return_value=True),
            patch(_CC_PATCH_TARGET) as mock_cc,
        ):
            result = runner.invoke(
                app,
                [
                    "bootstrap",
                    "-d",
                    "/tmp/test_url_ext",
                    "-u",
                    "https://example.com/repo.git",
                    "-t",
                    "external",
                    "--no_input",
                ],
            )
            assert result.exit_code == 0
            assert "cpex/templates/external" in mock_cc.call_args.kwargs["directory"]

    def test_explicit_url_exits_if_git_missing(self):
        with (
            patch("cpex.tools.cli.command_exists", return_value=False),
            patch(_CC_PATCH_TARGET) as mock_cc,
        ):
            result = runner.invoke(
                app,
                [
                    "bootstrap",
                    "-d",
                    "/tmp/test_url_nogit",
                    "-u",
                    "https://example.com/repo.git",
                    "--no_input",
                ],
            )
            assert result.exit_code == 1
            mock_cc.assert_not_called()


class TestBootstrapRemoteFallback:
    """Test bootstrap falls back to remote URL when local templates are missing."""

    def test_falls_back_to_default_remote_when_local_missing(self):
        with (
            patch("cpex.tools.cli.LOCAL_TEMPLATES_DIR", Path("/nonexistent/templates")),
            patch("cpex.tools.cli.command_exists", return_value=True),
            patch(_CC_PATCH_TARGET) as mock_cc,
        ):
            runner.invoke(app, ["bootstrap", "-d", "/tmp/test_remote", "--no_input"])
            mock_cc.assert_called_once()
            assert mock_cc.call_args.kwargs["template"] == DEFAULT_TEMPLATE_URL
            assert mock_cc.call_args.kwargs["checkout"] == "main"
            assert "cpex/templates/native" in mock_cc.call_args.kwargs["directory"]

    def test_falls_back_to_default_remote_with_custom_vcs_ref(self):
        with (
            patch("cpex.tools.cli.LOCAL_TEMPLATES_DIR", Path("/nonexistent/templates")),
            patch("cpex.tools.cli.command_exists", return_value=True),
            patch(_CC_PATCH_TARGET) as mock_cc,
        ):
            runner.invoke(app, ["bootstrap", "-d", "/tmp/test_ref", "--vcs_ref", "v1.0", "--no_input"])
            mock_cc.assert_called_once()
            assert mock_cc.call_args.kwargs["checkout"] == "v1.0"

    def test_warns_when_no_local_and_no_git(self):
        with (
            patch("cpex.tools.cli.LOCAL_TEMPLATES_DIR", Path("/nonexistent/templates")),
            patch("cpex.tools.cli.command_exists", return_value=False),
            patch(_CC_PATCH_TARGET) as mock_cc,
            patch("cpex.tools.cli.logger") as mock_logger,
            patch("cpex.tools.cli.console") as mock_console,
        ):
            result = runner.invoke(app, ["bootstrap", "-d", "/tmp/test_nogit", "--no_input"])
            assert result.exit_code == 4  # EXIT_OPERATION_FAILED
            mock_cc.assert_not_called()
            mock_logger.error.assert_called_once()


class TestBootstrapErrorHandling:
    """Test bootstrap error handling."""

    def test_logs_exception_on_cookiecutter_error(self):
        with (
            patch(_CC_PATCH_TARGET, side_effect=RuntimeError("template error")),
            patch("cpex.tools.cli.logger") as mock_logger,
            patch("cpex.tools.cli.console") as mock_console,
        ):
            result = runner.invoke(app, ["bootstrap", "-d", "/tmp/test_err", "--no_input"])
            assert result.exit_code == 4  # EXIT_OPERATION_FAILED
            mock_logger.exception.assert_called_once()


class TestBootstrapIntegration:
    """Integration tests that actually generate plugin directories."""

    def test_native_template_generates_files(self, tmp_path):
        dest = tmp_path / "my_native_plugin"
        result = runner.invoke(app, ["bootstrap", "-d", str(dest), "-t", "native", "--no_input"])
        assert result.exit_code == 0
        assert dest.is_dir()
        assert (dest / "plugin.py").is_file()
        assert (dest / "config.yaml").is_file()
        assert (dest / "plugin-manifest.yaml").is_file()
        assert (dest / "__init__.py").is_file()
        assert (dest / "README.md").is_file()

    def test_external_template_generates_files(self, tmp_path):
        dest = tmp_path / "my_external_plugin"
        result = runner.invoke(app, ["bootstrap", "-d", str(dest), "-t", "external", "--no_input"])
        assert result.exit_code == 0
        assert dest.is_dir()
        assert (dest / "pyproject.toml").is_file()
        assert (dest / "Makefile").is_file()
        assert (dest / "README.md").is_file()
        assert (dest / "Containerfile").is_file()
        assert (dest / "my_external_plugin" / "plugin.py").is_file()
        assert (dest / "tests").is_dir()

    def test_plugin_slug_is_used_as_directory_name(self, tmp_path):
        dest = tmp_path / "custom_slug"
        result = runner.invoke(app, ["bootstrap", "-d", str(dest), "-t", "native", "--no_input"])
        assert result.exit_code == 0
        assert dest.name == "custom_slug"
        assert dest.is_dir()


class TestMainEntrypoint:
    """Test the main() entrypoint."""

    def test_main_invokes_app(self):
        with patch("cpex.tools.cli.app") as mock_app:
            from cpex.tools.cli import main

            main()
            mock_app.assert_called_once()



# ---------------------------------------------------------------------------
# Plugin management function tests
# ---------------------------------------------------------------------------


class TestListFunction:
    """Tests for the list() function."""

    def test_list_with_no_registry_file(self, temp_registry_dir):
        """Test list when registry file doesn't exist."""
        with patch("cpex.tools.cli.logger") as mock_logger:
            list_registered_plugins("all")
            mock_logger.info.assert_called_with("No plugins registered.")

    def test_list_with_existing_plugins(self, temp_registry_dir):
        """Test list with existing plugins in registry."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "kind": "native",
                    "version": "1.0.0",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                },
                {
                    "name": "another_plugin",
                    "kind": "external",
                    "version": "2.0.0",
                    "installation_type": "pypi",
                    "installation_path": "/path/to/another_plugin",
                    "installed_at": "2024-01-02T00:00:00.000000Z",
                    "installed_by": "test_user",
                },
            ]
        }
        registry_file.write_text(json.dumps(registry_data))

        with patch("cpex.tools.cli.console") as mock_console:
            list_registered_plugins("all")
            assert mock_console.print.call_count == 2


class TestUpdatePluginRegistry:
    """Tests for update_plugin_registry() function."""

    def test_creates_new_registry_if_not_exists(self, temp_registry_dir):
        """Test creating a new registry when file doesn't exist."""
        manifest = create_test_manifest()
        
        mock_catalog = Mock()

        with (
              patch("cpex.tools.cli.git_user_name", return_value="test_user"),
              patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/to/plugin")),
              ):
            plugin_registry = PluginRegistry()
            plugin_registry.update(manifest, "monorepo", mock_catalog, "test_user")
            registry_file = temp_registry_dir / "installed-plugins.json"
            assert registry_file.exists()

    def test_updates_existing_registry(self, temp_registry_dir):
        """Test updating an existing registry."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {"plugins": []}
        registry_file.write_text(json.dumps(registry_data))

        manifest = create_test_manifest(
            name="new_plugin",
            version="2.0.0",
            kind="external",
            monorepo=Monorepo(package_source="https://example.com/repo#subdirectory=new_plugin", repo_url="https://example.com/repo", package_folder="new_plugin"),
        )
        
        mock_catalog = Mock()

        with (
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/to/new_plugin")),
        ):
            plugin_registry = PluginRegistry()
            plugin_registry.update(manifest, "monorepo", mock_catalog, "test_user")
            updated_data = json.loads(registry_file.read_text())
            assert len(updated_data["plugins"]) == 1
            assert updated_data["plugins"][0]["name"] == "new_plugin"


class TestPluginRegistryCoverage:
    """Additional tests to increase coverage for PluginRegistry."""

    def test_update_with_pypi_installation(self, temp_registry_dir):
        """Test registry update for the PyPI installation path."""
        manifest = create_test_manifest(
            name="pypi_plugin",
            monorepo=None,
            package_info=PyPiRepo(pypi_package="pypi-plugin", version_constraint=None),
        )

        mock_catalog = Mock()

        with patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/to/pypi_plugin")):
            plugin_registry = PluginRegistry()
            plugin_registry.update(manifest, "pypi", mock_catalog, "test_user")

            registry_file = temp_registry_dir / "installed-plugins.json"
            updated_data = json.loads(registry_file.read_text())
            assert len(updated_data["plugins"]) == 1
            assert updated_data["plugins"][0]["name"] == "pypi_plugin"
            assert updated_data["plugins"][0]["package_source"] == "pypi-plugin"
            assert updated_data["plugins"][0]["installation_type"] == "pypi"

    def test_update_raises_for_monorepo_without_monorepo_metadata(self, temp_registry_dir):
        """Test monorepo update fails when manifest.monorepo is missing."""
        manifest = create_test_manifest(monorepo=None)

        plugin_registry = PluginRegistry()

        with pytest.raises(RuntimeError, match="PluginManifest.monorepo can not be None."):
            plugin_registry.update(manifest, "monorepo", Mock(), "test_user")

    def test_update_raises_for_pypi_without_package_info(self, temp_registry_dir):
        """Test PyPI update fails when manifest.package_info is missing."""
        manifest = create_test_manifest(monorepo=None)

        plugin_registry = PluginRegistry()

        with pytest.raises(RuntimeError, match="PluginManifest.package_info can not be None."):
            plugin_registry.update(manifest, "pypi", Mock(), "test_user")

    def test_update_raises_for_invalid_installation_type(self, temp_registry_dir):
        """Test invalid installation types are rejected."""
        manifest = create_test_manifest()

        plugin_registry = PluginRegistry()

        with pytest.raises(ValueError, match="Invalid installation type: invalid"):
            plugin_registry.update(manifest, "invalid", Mock(), "test_user")
    
    def test_update_with_local_installation_and_explicit_plugin_path(self, temp_registry_dir):
        """Test registry update for local installation with explicit plugin_path."""
        manifest = create_test_manifest(monorepo=None, package_info=None)
        manifest.local = "/tmp/local-plugin-source"
        explicit_path = temp_registry_dir / "installed" / "local_plugin"
        explicit_path.mkdir(parents=True)

        plugin_registry = PluginRegistry()
        plugin_registry.update(manifest, "local", Mock(), "test_user", plugin_path=explicit_path, editable=True)

        registry_file = temp_registry_dir / "installed-plugins.json"
        updated_data = json.loads(registry_file.read_text())
        assert len(updated_data["plugins"]) == 1
        assert updated_data["plugins"][0]["name"] == manifest.name
        assert updated_data["plugins"][0]["package_source"] == "/tmp/local-plugin-source"
        assert updated_data["plugins"][0]["installation_type"] == "local"
        assert updated_data["plugins"][0]["installation_path"] == str(explicit_path.resolve())
        assert updated_data["plugins"][0]["editable"] is True

    def test_update_with_local_installation_raises_without_local_metadata(self, temp_registry_dir):
        """Test local update fails when manifest.local is missing."""
        manifest = create_test_manifest(monorepo=None, package_info=None)
        manifest.local = None

        plugin_registry = PluginRegistry()

        with pytest.raises(RuntimeError, match="PluginManifest local path can not be None."):
            plugin_registry.update(manifest, "local", Mock(), "test_user")

    def test_update_uses_find_package_path_when_plugin_path_not_provided(self, temp_registry_dir):
        """Test registry update falls back to find_package_path when plugin_path is omitted."""
        manifest = create_test_manifest()

        with patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/from/find_package_path")):
            plugin_registry = PluginRegistry()
            plugin_registry.update(manifest, "monorepo", Mock(), "test_user")

        registry_file = temp_registry_dir / "installed-plugins.json"
        updated_data = json.loads(registry_file.read_text())
        assert updated_data["plugins"][0]["installation_path"] == str(Path("/fake/path/from/find_package_path").resolve())

    def test_has_returns_true_when_plugin_present(self, temp_registry_dir):
        """Test has() returns True for an installed plugin."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))

        plugin_registry = PluginRegistry()

        assert plugin_registry.has("test_plugin") is True

    def test_has_returns_false_when_plugin_absent(self, temp_registry_dir):
        """Test has() returns False for a missing plugin."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_file.write_text(json.dumps({"plugins": []}))

        plugin_registry = PluginRegistry()

        assert plugin_registry.has("missing_plugin") is False


class TestInstanceNameIsUnique:
    """Tests for instance_name_is_unique() function."""

    def test_returns_true_for_unique_name(self):
        """Test that unique names return True."""
        existing_plugin = PluginConfig(
            name="existing_plugin",
            kind="test.plugin",
            mode=PluginMode.SEQUENTIAL,
            priority=100
        )
        
        config = Config(plugins=[existing_plugin])
        assert instance_name_is_unique(config, "new_plugin") is True

    def test_returns_false_for_duplicate_name(self):
        """Test that duplicate names return False."""
        existing_plugin = PluginConfig(
            name="existing_plugin",
            kind="test.plugin",
            mode=PluginMode.SEQUENTIAL,
            priority=100
        )
        
        config = Config(plugins=[existing_plugin])
        assert instance_name_is_unique(config, "existing_plugin") is False

    def test_returns_true_for_empty_config(self):
        """Test that any name is unique in empty config."""
        config = Config(plugins=[])
        assert instance_name_is_unique(config, "any_plugin") is True


class TestUpdatePluginsConfigYaml:
    """Tests for update_plugins_config_yaml() function."""

    def test_updates_config_with_unique_name(self, tmp_path):
        """Test updating config with a unique plugin name."""
        manifest = create_test_manifest()
        config_file = tmp_path / "config.yaml"
        
        mock_config = Config(plugins=[])
        
        with (
            patch("cpex.tools.cli.ConfigLoader.load_config", return_value=mock_config),
            patch("cpex.tools.cli.ConfigSaver.save_config") as mock_save,
            patch.object(type(manifest), "suggest_instance_name", return_value="test_plugin"),
            patch.object(type(manifest), "create_instance_config", return_value=PluginConfig(
                name="test_plugin",
                kind="test.plugin",
                mode=PluginMode.SEQUENTIAL,
                priority=100
            )),
        ):
            update_plugins_config_yaml(manifest)
            mock_save.assert_called_once()
            # Verify a plugin was added to the config
            assert mock_config.plugins is not None
            assert len(mock_config.plugins) == 1

    def test_generates_unique_name_when_duplicate(self, tmp_path):
        """Test that duplicate names get suffixed with counter."""
        manifest = create_test_manifest(name="test_plugin")
        config_file = tmp_path / "config.yaml"
        
        # Create existing plugin with same suggested name
        existing_plugin = PluginConfig(
            name="test_plugin",
            kind="test.plugin",
            mode=PluginMode.SEQUENTIAL,
            priority=100
        )
        mock_config = Config(plugins=[existing_plugin])
        
        with (
            patch("cpex.tools.cli.ConfigLoader.load_config", return_value=mock_config),
            patch("cpex.tools.cli.ConfigSaver.save_config") as mock_save,
            patch.object(type(manifest), "suggest_instance_name", return_value="test_plugin"),
            patch.object(type(manifest), "create_instance_config", return_value=PluginConfig(
                name="test_plugin_1",
                kind="test.plugin",
                mode=PluginMode.SEQUENTIAL,
                priority=100
            )),
        ):
            update_plugins_config_yaml(manifest)
            mock_save.assert_called_once()
            # Verify a new plugin was added
            assert mock_config.plugins is not None
            assert len(mock_config.plugins) == 2
            # The new plugin should have a different name (with suffix)
            assert mock_config.plugins[1].name != "test_plugin"


class TestInstallFromManifest:
    """Tests for install_from_manifest() function."""

    def test_install_from_monorepo(self, temp_registry_dir):
        """Test installing from monorepo."""
        manifest = create_test_manifest()

        mock_catalog = Mock()
        mock_catalog.install_folder_via_pip = Mock()

        with (
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.cli.update_plugins_config_yaml"),
            patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/to/plugin")),
        ):
            install_from_manifest(manifest, "monorepo", mock_catalog)
            mock_catalog.install_folder_via_pip.assert_called_once_with(manifest)


class TestInstallFunction:
    """Tests for install() function."""

    def test_install_git_implementation(self):
        """Test that git installation works with install_from_git."""
        mock_catalog = Mock()
        test_manifest = create_test_manifest(name="test_plugin", kind="native")
        mock_catalog.install_from_git = Mock(return_value=(test_manifest, Path("/path/to/plugin")))
        
        with (
            patch("cpex.tools.cli._finalize_installation") as mock_finalize,
            patch("cpex.tools.cli.console") as mock_console,
            patch("cpex.tools.cli.update_plugins_config_yaml") as mock_update_config,
        ):
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            install("test_plugin @ git+https://github.com/example/test_plugin.git", "git", mock_catalog)

            # Verify install_from_git was called
            mock_catalog.install_from_git.assert_called_once()
            # update_plugins_config_yaml is called inside _finalize_installation (mocked),
            # not directly from _install_from_git — verify no duplicate direct call.
            mock_update_config.assert_not_called()
            mock_finalize.assert_called_once()

    def test_install_monorepo_no_plugins_found(self):
        """Test monorepo install when no plugins found."""
        mock_catalog = Mock()
        mock_catalog.search = Mock(return_value=None)

        with patch("cpex.tools.cli.console") as mock_logger:
            install("test_plugin", "monorepo", mock_catalog)
            mock_logger.print.assert_called_with("No matching plugins found.")

    def test_install_monorepo_with_available_plugins(self, temp_registry_dir):
        """Test monorepo install with available plugins."""
        manifest = create_test_manifest()

        mock_catalog = Mock()
        mock_catalog.search = Mock(return_value=[manifest])
        mock_catalog.install_folder_via_pip = Mock()

        with (
            patch("cpex.tools.cli.inquirer.prompt", return_value={"plugins": 0}),
            patch("cpex.tools.cli.Console"),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.cli.update_plugins_config_yaml"),
            patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/to/plugin")),
        ):
            install("test_plugin", "monorepo", mock_catalog)
            mock_catalog.install_folder_via_pip.assert_called_once()

    def test_install_requires_type_parameter(self):
        """Test that install raises typer.Exit for unsupported type."""
        mock_catalog = Mock()
        with (
            patch("cpex.tools.cli.console") as mock_console,
            pytest.raises(click.exceptions.Exit) as exc_info,
        ):
            install("source", "", mock_catalog)
        assert exc_info.value.exit_code == 2  # EXIT_INVALID_ARGS


class TestSearchFunction:
    """Tests for search() function."""

    def test_search_with_results(self):
        """Test search with matching plugins."""
        manifest = create_test_manifest()

        mock_catalog = Mock()
        mock_catalog.search = Mock(return_value=[manifest])

        with patch("cpex.tools.cli.console") as mock_console:
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            search("test", mock_catalog)
            mock_console.log.assert_called()

    def test_search_with_no_results(self):
        """Test search with no matching plugins."""
        mock_catalog = Mock()
        mock_catalog.search = Mock(return_value=None)

        with patch("cpex.tools.cli.console") as mock_console:
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            search("nonexistent", mock_catalog)
            mock_console.log.assert_called_with("No plugins found.")


class TestInfoFunction:
    """Tests for info() function."""

    def test_info_with_no_registry(self, temp_registry_dir):
        """Test info when registry doesn't exist."""
        with patch("cpex.tools.cli.console") as mock_console:
            info(None)
            mock_console.print.assert_called_with("No plugins found")

    def test_info_list_all_plugins(self, temp_registry_dir):
        """Test info listing all plugins."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "plugins",
                    "installed_at": "2024-01-01T00:00:00Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))

        with patch("cpex.tools.cli.console") as mock_console:
            info(None)
            mock_console.print_json.assert_called_once()

    def test_info_search_specific_plugin(self, temp_registry_dir):
        """Test info searching for specific plugin."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "plugins",
                    "installed_at": "2024-01-01T00:00:00Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                },
                {
                    "name": "another_plugin",
                    "version": "2.0.0",
                    "kind": "external",
                    "installation_type": "pypi",
                    "installation_path": "plugins",
                    "installed_at": "2024-01-01T00:00:00Z",
                    "installed_by": "test_user",
                    "package_source": "https://pypi.org/project/another_plugin",
                    "editable": False,
                },
            ]
        }
        registry_file.write_text(json.dumps(registry_data))

        with patch("cpex.tools.cli.console") as mock_console:
            info("test")
            mock_console.print_json.assert_called_once()


class TestPluginCommand:
    """Tests for the plugin() command."""

    def test_plugin_info_command(self, temp_registry_dir):
        """Test plugin info command."""
        with patch("cpex.tools.cli.Console"):
            result = runner.invoke(app, ["plugin", "info"])
            assert result.exit_code == 0

    def test_plugin_list_command(self, temp_registry_dir):
        """Test plugin list command."""
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.Console"),
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_pyproject = Mock()
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "list"])
            assert result.exit_code == 0
            mock_catalog.update_catalog_with_pyproject.assert_called_once()

    def test_plugin_search_command(self, temp_registry_dir):
        """Test plugin search command."""
        manifest = create_test_manifest()

        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.Console"),
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_pyproject = Mock()
            mock_catalog.search = Mock(return_value=[manifest])
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "search", "test"])
            assert result.exit_code == 0
            mock_catalog.search.assert_called_once_with("test")

    def test_plugin_install_command(self, temp_registry_dir):
        """Test plugin install command."""
        manifest = create_test_manifest()

        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.Console"),
            patch("cpex.tools.cli.inquirer.prompt", return_value={"plugins": 0}),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.cli.update_plugins_config_yaml"),
            patch("cpex.tools.plugin_registry.find_package_path", return_value=Path("/fake/path/to/plugin")),
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_pyproject = Mock()
            mock_catalog.search = Mock(return_value=[manifest])
            mock_catalog.install_folder_via_pip = Mock()
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "install", "test_plugin", "--type", "monorepo"])
            assert result.exit_code == 0


class TestCallbackFunction:
    """Tests for the callback() function."""

    def test_callback_exists(self):
        """Test that callback function exists."""
        from cpex.tools.cli import callback

        # callback should be callable and do nothing
        callback()



class TestRemoveFromPluginsConfigYaml:
    """Tests for remove_from_plugins_config_yaml() function."""

    def test_removes_plugin_from_config(self, tmp_path):
        """Test removing a plugin from config."""
        config_file = tmp_path / "config.yaml"
        
        plugin1 = PluginConfig(
            name="plugin_to_remove",
            kind="test.plugin.remove",
            mode=PluginMode.SEQUENTIAL,
            priority=100
        )
        plugin2 = PluginConfig(
            name="plugin_to_keep",
            kind="test.plugin.keep",
            mode=PluginMode.SEQUENTIAL,
            priority=100
        )
        mock_config = Config(plugins=[plugin1, plugin2])
        
        # Create a manifest with matching kind
        manifest = create_test_manifest(name="plugin_to_remove", kind="test.plugin.remove")
        
        with (
            patch("cpex.tools.cli.ConfigLoader.load_config", return_value=mock_config),
            patch("cpex.tools.cli.ConfigSaver.save_config") as mock_save,
        ):
            result = remove_from_plugins_config_yaml(manifest)
            assert result is True
            mock_save.assert_called_once()
            assert len(mock_config.plugins) == 1
            assert mock_config.plugins[0].kind == "test.plugin.keep"

    def test_removes_isolated_venv_plugin_from_config(self, tmp_path):
        """Test removing a plugin from config."""
        config_file = tmp_path / "config.yaml"
        
        config_1 = {
                "class_name": "test.plugin.remove",
                "requirements_file": "requirements.txt"
        }

        config_2 = {
                "class_name": "test.plugin.keep",
                "requirements_file": "requirements.txt"
        }

        plugin1 = PluginConfig(
            name="plugin_to_remove",
            kind="isolated_venv",
            mode=PluginMode.SEQUENTIAL,
            priority=100,
            config=config_1
        )
        plugin2 = PluginConfig(
            name="plugin_to_keep",
            kind="test.plugin.keep",
            mode=PluginMode.SEQUENTIAL,
            priority=100,
            config=config_2
        )
        mock_config = Config(plugins=[plugin1, plugin2])
        
        # Create a manifest with matching kind
        manifest = create_test_manifest(
                name="plugin_to_remove",
                kind="isolated_venv",
                default_config=config_1
            )
        
        with (
            patch("cpex.tools.cli.ConfigLoader.load_config", return_value=mock_config),
            patch("cpex.tools.cli.ConfigSaver.save_config") as mock_save,
        ):
            result = remove_from_plugins_config_yaml(manifest)
            assert result is True
            mock_save.assert_called_once()
            assert len(mock_config.plugins) == 1
            assert mock_config.plugins[0].kind == "test.plugin.keep"


    def test_returns_false_when_plugin_not_found(self, tmp_path):
        """Test that function returns False when plugin not found."""
        plugin1 = PluginConfig(
            name="existing_plugin",
            kind="test.plugin.existing",
            mode=PluginMode.SEQUENTIAL,
            priority=100
        )
        mock_config = Config(plugins=[plugin1])
        
        # Create a manifest with non-matching kind
        manifest = create_test_manifest(name="nonexistent_plugin", kind="test.plugin.nonexistent")
        
        with (
            patch("cpex.tools.cli.ConfigLoader.load_config", return_value=mock_config),
            patch("cpex.tools.cli.ConfigSaver.save_config") as mock_save,
        ):
            result = remove_from_plugins_config_yaml(manifest)
            assert result is False
            mock_save.assert_not_called()

    def test_returns_false_when_no_plugins_in_config(self, tmp_path):
        """Test that function returns False when config has no plugins."""
        mock_config = Config(plugins=None)
        manifest = create_test_manifest(name="any_plugin")
        
        with patch("cpex.tools.cli.ConfigLoader.load_config", return_value=mock_config):
            result = remove_from_plugins_config_yaml(manifest)
            assert result is False

    def test_handles_exception_gracefully(self, tmp_path):
        """Test that function handles exceptions gracefully."""
        manifest = create_test_manifest(name="any_plugin")
        
        with (
            patch("cpex.tools.cli.ConfigLoader.load_config", side_effect=Exception("Config error")),
            patch("cpex.tools.cli.logger") as mock_logger,
        ):
            result = remove_from_plugins_config_yaml(manifest)
            assert result is False
            mock_logger.error.assert_called_once()


class TestUninstallFunction:
    """Tests for uninstall() function."""

    def test_uninstall_plugin_not_found(self, temp_registry_dir):
        """Test uninstalling a plugin that is not installed."""
        mock_catalog = Mock()
        
        with (
            patch("cpex.tools.cli.console") as mock_console,
            pytest.raises(click.exceptions.Exit) as exc_info,
        ):
            uninstall("nonexistent_plugin", mock_catalog)
        assert exc_info.value.exit_code == 3  # EXIT_NOT_FOUND
        mock_console.print.assert_called_with(":x: Plugin 'nonexistent_plugin' is not installed.")

    def test_uninstall_cancelled_by_user(self, temp_registry_dir):
        """Test uninstall cancelled by user."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))
        
        mock_catalog = Mock()
        
        with (
            patch("cpex.tools.cli.inquirer.prompt", return_value={"confirm": False}),
            patch("cpex.tools.cli.console") as mock_console,
        ):
            uninstall("test_plugin", mock_catalog)
            mock_console.print.assert_any_call("Uninstall cancelled.")

    def test_uninstall_success(self, temp_registry_dir):
        """Test successful plugin uninstallation."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))
        
        mock_catalog = Mock()
        
        # Create a manifest to return from find
        test_manifest = create_test_manifest(name="test_plugin", kind="native")
        
        with (
            patch("cpex.tools.cli.inquirer.prompt", return_value={"confirm": True}),
            patch("cpex.tools.cli.console") as mock_console,
            patch("cpex.tools.cli.remove_from_plugins_config_yaml", return_value=True) as mock_remove,
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
        ):
            # Mock the catalog instance created inside uninstall()
            mock_catalog_instance = Mock()
            mock_catalog_instance.find = Mock(return_value=test_manifest)
            mock_catalog_instance.uninstall_package = Mock()
            mock_catalog_class.return_value = mock_catalog_instance
            
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            uninstall("test_plugin", mock_catalog)
            
            # Verify uninstall_package was called with both plugin_name and manifest
            mock_catalog_instance.uninstall_package.assert_called_once_with("test_plugin", test_manifest)
            mock_remove.assert_called_once_with(test_manifest)
            mock_console.print.assert_any_call(":white_heavy_check_mark: test_plugin uninstalled successfully.")

    def test_uninstall_handles_exception(self, temp_registry_dir):
        """Test uninstall handles exceptions gracefully."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))

        mock_catalog = Mock()

        # Create a manifest to return from find
        test_manifest = create_test_manifest(name="test_plugin", kind="native")

        with (
            patch("cpex.tools.cli.inquirer.prompt", return_value={"confirm": True}),
            patch("cpex.tools.cli.console") as mock_console,
            patch("cpex.tools.cli.logger") as mock_logger,
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            pytest.raises(click.exceptions.Exit) as exc_info,
        ):
            # Mock the catalog instance created inside uninstall()
            mock_catalog_instance = Mock()
            mock_catalog_instance.find = Mock(return_value=test_manifest)
            mock_catalog_instance.uninstall_package = Mock(side_effect=RuntimeError("Uninstall failed"))
            mock_catalog_class.return_value = mock_catalog_instance

            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)

            uninstall("test_plugin", mock_catalog)

        assert exc_info.value.exit_code == 4  # EXIT_OPERATION_FAILED
        mock_console.print.assert_any_call(":x: Failed to uninstall test_plugin: Uninstall failed")
        mock_logger.error.assert_called_once()


class TestPluginUninstallCommand:
    """Tests for the plugin uninstall command."""

    def test_plugin_uninstall_command_without_plugin_name(self, temp_registry_dir):
        """Test plugin uninstall command without specifying plugin name."""
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.console") as mock_console,
        ):
            mock_catalog = Mock()
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "uninstall"])
            assert result.exit_code == 2  # EXIT_INVALID_ARGS
            mock_console.print.assert_called_with(":x: Please specify a plugin name to uninstall.")

    def test_plugin_uninstall_command_success(self, temp_registry_dir):
        """Test successful plugin uninstall command."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))
        
        # Create a manifest to return from find
        test_manifest = create_test_manifest(name="test_plugin", kind="native")
        
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.inquirer.prompt", return_value={"confirm": True}),
            patch("cpex.tools.cli.console") as mock_console,
            patch("cpex.tools.cli.remove_from_plugins_config_yaml", return_value=True),
        ):
            mock_catalog = Mock()
            mock_catalog.uninstall_package = Mock()
            mock_catalog.find = Mock(return_value=test_manifest)
            mock_catalog_class.return_value = mock_catalog
            
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            result = runner.invoke(app, ["plugin", "uninstall", "test_plugin"])
            assert result.exit_code == 0
            # Verify uninstall_package was called with both plugin_name and manifest
            mock_catalog.uninstall_package.assert_called_once_with("test_plugin", test_manifest)

    def test_plugin_uninstall_command_not_found(self, temp_registry_dir):
        """Test plugin uninstall command when plugin not found."""
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.console") as mock_console,
        ):
            mock_catalog = Mock()
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "uninstall", "nonexistent_plugin"])
            assert result.exit_code == 3  # EXIT_NOT_FOUND
            mock_console.print.assert_called_with(":x: Plugin 'nonexistent_plugin' is not installed.")


class TestCatalogUninstallPackage:
    """Tests for PluginCatalog.uninstall_package() method."""

    def test_uninstall_package_success(self, temp_registry_dir):
        """Test successful package uninstallation."""
        from cpex.tools.catalog import PluginCatalog
        
        # Create a test manifest
        test_manifest = create_test_manifest(name="test_package", kind="native")
        
        with (
            patch.dict("os.environ", {"PLUGINS_GITHUB_TOKEN": "test_token"}),
            patch("cpex.tools.catalog.Github"),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
        ):
            catalog = PluginCatalog()
            result = catalog.uninstall_package("test_package", test_manifest)
            
            assert result is True
            mock_subprocess.assert_called_once()
            call_args = mock_subprocess.call_args
            assert "pip" in call_args[0][0]
            assert "uninstall" in call_args[0][0]
            assert "-y" in call_args[0][0]
            assert "test_package" in call_args[0][0]

    def test_uninstall_package_subprocess_error(self, temp_registry_dir):
        """Test package uninstallation with subprocess error."""
        from cpex.tools.catalog import PluginCatalog
        import subprocess
        
        # Create a test manifest
        test_manifest = create_test_manifest(name="test_package", kind="native")
        
        with (
            patch.dict("os.environ", {"PLUGINS_GITHUB_TOKEN": "test_token"}),
            patch("cpex.tools.catalog.Github"),
            patch("cpex.tools.catalog.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["pip"], stderr="Error")),
        ):
            catalog = PluginCatalog()
            
            with pytest.raises(RuntimeError, match="Failed to uninstall"):
                catalog.uninstall_package("test_package", test_manifest)

    def test_uninstall_package_unexpected_error(self, temp_registry_dir):
        """Test package uninstallation with unexpected error."""
        from cpex.tools.catalog import PluginCatalog
        
        # Create a test manifest
        test_manifest = create_test_manifest(name="test_package", kind="native")
        
        with (
            patch.dict("os.environ", {"PLUGINS_GITHUB_TOKEN": "test_token"}),
            patch("cpex.tools.catalog.Github"),
            patch("cpex.tools.catalog.subprocess.run", side_effect=Exception("Unexpected error")),
        ):
            catalog = PluginCatalog()
            
            with pytest.raises(RuntimeError, match="Unexpected error uninstalling"):
                catalog.uninstall_package("test_package", test_manifest)


class TestPluginRegistryRemove:
    """Tests for PluginRegistry.remove() method."""

    def test_remove_existing_plugin(self, temp_registry_dir):
        """Test removing an existing plugin from registry."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))
        
        plugin_registry = PluginRegistry()
        result = plugin_registry.remove("test_plugin")
        
        assert result is True
        updated_data = json.loads(registry_file.read_text())
        assert len(updated_data["plugins"]) == 0

    def test_remove_nonexistent_plugin(self, temp_registry_dir):
        """Test removing a plugin that doesn't exist."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))
        
        plugin_registry = PluginRegistry()
        result = plugin_registry.remove("nonexistent_plugin")
        
        assert result is False
        updated_data = json.loads(registry_file.read_text())
        assert len(updated_data["plugins"]) == 1


class TestInstalledPluginRegistryUnregister:
    """Tests for InstalledPluginRegistry.unregister_plugin() method."""

    def test_unregister_existing_plugin(self, temp_registry_dir):
        """Test unregistering an existing plugin."""
        from cpex.framework.models import InstalledPluginRegistry, InstalledPluginInfo, PluginInstallationType
        
        registry_file = temp_registry_dir / "installed-plugins.json"
        plugin1 = InstalledPluginInfo(
            name="plugin1",
            kind="native",
            version="1.0.0",
            installation_type=PluginInstallationType.MONOREPO,
            installation_path="/path/to/plugin1",
            installed_at="2024-01-01T00:00:00.000000Z",
            installed_by="test_user",
            package_source="https://example.com/repo/plugin1",
            editable=False,
        )
        plugin2 = InstalledPluginInfo(
            name="plugin2",
            kind="native",
            version="1.0.0",
            installation_type=PluginInstallationType.MONOREPO,
            installation_path="/path/to/plugin2",
            installed_at="2024-01-01T00:00:00.000000Z",
            installed_by="test_user",
            package_source="https://example.com/repo/plugin2",
            editable=False,
        )
        
        registry = InstalledPluginRegistry(plugins=[plugin1, plugin2])
        result = registry.unregister_plugin("plugin1")
        
        assert result is True
        assert len(registry.plugins) == 1
        assert registry.plugins[0].name == "plugin2"

    def test_unregister_nonexistent_plugin(self, temp_registry_dir):
        """Test unregistering a plugin that doesn't exist."""
        from cpex.framework.models import InstalledPluginRegistry, InstalledPluginInfo, PluginInstallationType
        
        plugin1 = InstalledPluginInfo(
            name="plugin1",
            kind="native",
            version="1.0.0",
            installation_type=PluginInstallationType.MONOREPO,
            installation_path="/path/to/plugin1",
            installed_at="2024-01-01T00:00:00.000000Z",
            installed_by="test_user",
            package_source="https://example.com/repo/plugin1",
            editable=False,
        )
        
        registry = InstalledPluginRegistry(plugins=[plugin1])
        result = registry.unregister_plugin("nonexistent")
        
        assert result is False
        assert len(registry.plugins) == 1


class TestInstalledPluginRegistryRegisterDedup:
    """Tests for dedup behaviour of InstalledPluginRegistry.register_plugin()."""

    def _make_plugin(self, name="foo", version="1.0.0", path="/path/to/plugin", installed_at="2024-01-01T00:00:00.000000Z"):
        from cpex.framework.models import InstalledPluginInfo, PluginInstallationType
        return InstalledPluginInfo(
            name=name,
            kind="native",
            version=version,
            installation_type=PluginInstallationType.LOCAL,
            installation_path=path,
            installed_at=installed_at,
            installed_by="test_user",
            package_source="https://example.com/repo",
            editable=False,
        )

    def test_first_register_appends(self, temp_registry_dir):
        """Registering into an empty registry results in exactly one entry."""
        import json
        from cpex.framework.models import InstalledPluginRegistry

        registry = InstalledPluginRegistry()
        registry.register_plugin(self._make_plugin())

        assert len(registry.plugins) == 1
        registry_file = temp_registry_dir / "installed-plugins.json"
        data = json.loads(registry_file.read_text())
        assert len(data["plugins"]) == 1
        assert data["plugins"][0]["name"] == "foo"

    def test_reregister_replaces_existing(self, temp_registry_dir):
        """Registering a plugin that is already present replaces the old entry."""
        import json
        from cpex.framework.models import InstalledPluginRegistry

        registry = InstalledPluginRegistry()
        registry.register_plugin(self._make_plugin(version="1.0.0", installed_at="2024-01-01T00:00:00.000000Z"))
        registry.register_plugin(self._make_plugin(version="2.0.0", path="/new/path", installed_at="2025-06-01T00:00:00.000000Z"))

        assert len(registry.plugins) == 1
        assert registry.plugins[0].version == "2.0.0"
        assert registry.plugins[0].installation_path == "/new/path"
        assert registry.plugins[0].installed_at == "2025-06-01T00:00:00.000000Z"

        registry_file = temp_registry_dir / "installed-plugins.json"
        data = json.loads(registry_file.read_text())
        assert len(data["plugins"]) == 1
        assert data["plugins"][0]["version"] == "2.0.0"

    def test_reregister_does_not_affect_other_plugins(self, temp_registry_dir):
        """Re-registering one plugin leaves other plugins untouched."""
        from cpex.framework.models import InstalledPluginRegistry

        registry = InstalledPluginRegistry()
        registry.register_plugin(self._make_plugin(name="foo", version="1.0.0"))
        registry.register_plugin(self._make_plugin(name="bar", version="1.0.0"))
        registry.register_plugin(self._make_plugin(name="foo", version="2.0.0"))

        assert len(registry.plugins) == 2
        names = {p.name for p in registry.plugins}
        assert names == {"foo", "bar"}
        foo = next(p for p in registry.plugins if p.name == "foo")
        bar = next(p for p in registry.plugins if p.name == "bar")
        assert foo.version == "2.0.0"
        assert bar.version == "1.0.0"


class TestInstalledPluginRegistrySaveAtomic:
    """Tests for atomic write behaviour of InstalledPluginRegistry.save()."""

    def _make_plugin(self):
        from cpex.framework.models import InstalledPluginInfo, PluginInstallationType
        return InstalledPluginInfo(
            name="test_plugin",
            kind="native",
            version="1.0.0",
            installation_type=PluginInstallationType.MONOREPO,
            installation_path="/path/to/plugin",
            installed_at="2024-01-01T00:00:00.000000Z",
            installed_by="test_user",
            package_source="https://example.com/repo/plugin",
            editable=False,
        )

    def test_happy_path_no_tmp_litter(self, temp_registry_dir):
        """save() writes the file and leaves no .tmp siblings."""
        from cpex.framework.models import InstalledPluginRegistry
        registry = InstalledPluginRegistry()
        registry.register_plugin(self._make_plugin())

        registry_file = temp_registry_dir / "installed-plugins.json"
        assert registry_file.exists()
        data = json.loads(registry_file.read_text())
        assert len(data["plugins"]) == 1
        assert data["plugins"][0]["name"] == "test_plugin"
        assert [*temp_registry_dir.glob("installed-plugins.*.tmp")] == []

    def test_crash_mid_rename_preserves_original(self, temp_registry_dir, monkeypatch):
        """If os.replace raises, the original file is untouched and no .tmp remains."""
        import os
        from cpex.framework.models import InstalledPluginRegistry

        original_content = b'{"plugins":[]}'
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_file.write_bytes(original_content)

        def exploding_replace(*args, **kwargs):
            raise OSError("simulated mid-rename crash")

        monkeypatch.setattr(os, "replace", exploding_replace)

        registry = InstalledPluginRegistry()
        with pytest.raises(OSError, match="simulated mid-rename crash"):
            registry.save()

        assert registry_file.read_bytes() == original_content
        assert [*temp_registry_dir.glob("installed-plugins.*.tmp")] == []

    def test_crash_mid_write_cleans_up_tmp(self, temp_registry_dir, monkeypatch):
        """If writing to the temp file raises, the temp file is cleaned up."""
        import tempfile as _tempfile
        from cpex.framework.models import InstalledPluginRegistry

        original_NamedTemporaryFile = _tempfile.NamedTemporaryFile

        class _ExplodingFile:
            def __init__(self, *args, **kwargs):
                self._real = original_NamedTemporaryFile(*args, **kwargs)
                self.name = self._real.name

            def write(self, data):
                raise OSError("simulated write failure")

            def flush(self):
                pass

            def fileno(self):
                return self._real.fileno()

            def close(self):
                self._real.close()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        monkeypatch.setattr(_tempfile, "NamedTemporaryFile", _ExplodingFile)

        registry = InstalledPluginRegistry()
        with pytest.raises(OSError, match="simulated write failure"):
            registry.save()

        assert [*temp_registry_dir.glob("installed-plugins.*.tmp")] == []


class TestSelectPluginFromCatalog:
    """Tests for select_plugin_from_catalog() function."""

    def test_returns_none_for_empty_list(self):
        """Test that function returns None when given empty list."""
        from cpex.tools.cli import select_plugin_from_catalog
        
        result = select_plugin_from_catalog([])
        assert result is None

    def test_returns_none_when_user_cancels(self):
        """Test that function returns None when user cancels selection."""
        from cpex.tools.cli import select_plugin_from_catalog
        
        manifest = create_test_manifest()
        
        with patch("cpex.tools.cli.inquirer.prompt", return_value=None):
            result = select_plugin_from_catalog([manifest])
            assert result is None


class TestParsePypiSource:
    """Tests for _parse_pypi_source() function."""

    def test_parse_package_without_version(self):
        """Test parsing package name without version constraint."""
        from cpex.tools.cli import _parse_pypi_source
        
        package_name, version_constraint = _parse_pypi_source("my-package")
        assert package_name == "my-package"
        assert version_constraint is None

    def test_parse_package_with_version(self):
        """Test parsing package name with version constraint."""
        from cpex.tools.cli import _parse_pypi_source
        
        package_name, version_constraint = _parse_pypi_source("my-package@>=1.0.0")
        assert package_name == "my-package"
        assert version_constraint == ">=1.0.0"


class TestFinalizeInstallation:
    """Tests for _finalize_installation() function."""

    def test_finalize_installation_updates_registry_and_config(self, temp_registry_dir):
        """Test that finalize_installation updates registry and config."""
        from cpex.tools.cli import _finalize_installation
        from cpex.tools.catalog import PluginCatalog
        
        manifest = create_test_manifest()
        mock_catalog = Mock(spec=PluginCatalog)
        
        with (
            patch("cpex.tools.cli.PluginRegistry") as mock_registry_class,
            patch("cpex.tools.cli.update_plugins_config_yaml") as mock_update_config,
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
        ):
            mock_registry = Mock()
            mock_registry_class.return_value = mock_registry
            
            _finalize_installation(manifest, "pypi", mock_catalog, Path("/test/path"))
            
            mock_registry.update.assert_called_once()
            mock_update_config.assert_called_once_with(manifest=manifest)


class TestInstallFromLocal:
    """Tests for _install_from_local() function."""

    def test_install_from_local_calls_catalog_method(self, temp_registry_dir, tmp_path):
        """Test that _install_from_local calls catalog.install_from_local."""
        from cpex.tools.cli import _install_from_local
        from cpex.tools.catalog import PluginCatalog
        
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        
        manifest = create_test_manifest()
        manifest.local = str(source_dir)
        mock_catalog = Mock(spec=PluginCatalog)
        mock_catalog.install_from_local = Mock(return_value=(manifest, source_dir))
        
        with (
            patch("cpex.tools.cli.console") as mock_console,
            patch("cpex.tools.cli.update_plugins_config_yaml") as mock_update_config,
            patch("cpex.tools.cli._finalize_installation") as mock_finalize,
        ):
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            _install_from_local(str(source_dir), mock_catalog)
            
            mock_catalog.install_from_local.assert_called_once()
            # update_plugins_config_yaml is called inside _finalize_installation (mocked),
            # not directly from _install_from_local — verify no duplicate direct call.
            mock_update_config.assert_not_called()
            mock_finalize.assert_called_once_with(manifest, "local", mock_catalog, source_dir)


class TestInstallFromMonorepo:
    """Tests for _install_from_monorepo() function."""

    def test_returns_early_when_no_plugin_selected(self):
        """Test that function returns early when user doesn't select a plugin."""
        from cpex.tools.cli import _install_from_monorepo
        from cpex.tools.catalog import PluginCatalog
        
        manifest = create_test_manifest()
        mock_catalog = Mock(spec=PluginCatalog)
        mock_catalog.search = Mock(return_value=[manifest])
        
        with (
            patch("cpex.tools.cli.select_plugin_from_catalog", return_value=None),
            patch("cpex.tools.cli.console"),
        ):
            # Should return early without error
            _install_from_monorepo("test_plugin", mock_catalog)


class TestInstallFromPypi:
    """Tests for _install_from_pypi() function."""

    def test_install_from_pypi_handles_none_manifest(self, temp_registry_dir):
        """Test that _install_from_pypi handles None manifest gracefully."""
        from cpex.tools.cli import _install_from_pypi
        from cpex.tools.catalog import PluginCatalog
        
        mock_catalog = Mock(spec=PluginCatalog)
        mock_catalog.install_from_pypi = Mock(return_value=(None, None))
        
        with patch("cpex.tools.cli.console") as mock_console:
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            _install_from_pypi("test_package", mock_catalog)
            
            mock_console.print.assert_called_with(":x: Failed to install test_package")


class TestInstallFunctionAdditional:
    """Additional tests for install() function."""

    def test_install_with_unsupported_type_raises_error(self):
        """Test that install raises typer.Exit for unsupported installation type."""
        from cpex.tools.cli import install
        from cpex.tools.catalog import PluginCatalog
        
        mock_catalog = Mock(spec=PluginCatalog)
        
        with (
            patch("cpex.tools.cli.console") as mock_console,
            pytest.raises(click.exceptions.Exit) as exc_info,
        ):
            install("test_plugin", "unsupported_type", mock_catalog)
        assert exc_info.value.exit_code == 2  # EXIT_INVALID_ARGS


class TestVersionsFunction:
    """Tests for versions() function."""

    def test_versions_calls_search(self):
        """Test that versions() function calls search()."""
        from cpex.tools.cli import versions
        from cpex.tools.catalog import PluginCatalog
        
        mock_catalog = Mock(spec=PluginCatalog)
        mock_catalog.search = Mock(return_value=[])
        
        with patch("cpex.tools.cli.console"):
            versions("test_plugin", mock_catalog)
            mock_catalog.search.assert_called_once_with("test_plugin")


class TestUpdatePluginsConfigYamlWithNonePlugins:
    """Test update_plugins_config_yaml when config.plugins is None."""

    def test_creates_plugins_list_when_none(self, tmp_path):
        """Test that function creates plugins list when it's None."""
        import yaml as yaml_module
        
        config_file = tmp_path / "config.yaml"
        config_data = {
            "plugins": None,  # Explicitly None
        }
        config_file.write_text(yaml_module.safe_dump(config_data))
        
        manifest = create_test_manifest(name="test_plugin")
        
        with (
            patch("cpex.tools.cli.settings") as mock_settings,
            patch("cpex.tools.cli.ConfigLoader.load_config") as mock_load,
            patch("cpex.tools.cli.ConfigSaver.save_config") as mock_save,
        ):
            mock_settings.config_file = str(config_file)
            
            # Create a Config object with plugins=None
            config_obj = Config(plugins=None)
            mock_load.return_value = config_obj
            
            update_plugins_config_yaml(manifest)
            
            # Verify that plugins list was created
            mock_save.assert_called_once()
            saved_config = mock_save.call_args[0][0]
            assert saved_config.plugins is not None
            assert len(saved_config.plugins) == 1


class TestPluginCommandCatalogUpdate:
    """Tests for plugin command catalog update paths."""

    def test_plugin_search_updates_catalog(self, temp_registry_dir):
        """Test that plugin search command updates catalog."""
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.console") as mock_console,
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_pyproject = Mock(return_value=False)
            mock_catalog.search = Mock(return_value=[])
            mock_catalog_class.return_value = mock_catalog
            
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            result = runner.invoke(app, ["plugin", "search", "test"])
            assert result.exit_code == 0
            mock_catalog.update_catalog_with_pyproject.assert_called_once()

    def test_plugin_versions_command(self, temp_registry_dir):
        """Test plugin versions command."""
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.console") as mock_console,
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_pyproject = Mock(return_value=False)
            mock_catalog.search = Mock(return_value=[])
            mock_catalog_class.return_value = mock_catalog
            
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            result = runner.invoke(app, ["plugin", "versions", "test_plugin"])
            assert result.exit_code == 0
            mock_catalog.search.assert_called_once_with("test_plugin")


class TestUninstallManifestNotFound:
    """Test uninstall when manifest is not found in catalog."""

    def test_uninstall_when_manifest_not_found(self, temp_registry_dir):
        """Test uninstall handles case when manifest is not found."""
        registry_file = temp_registry_dir / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "kind": "native",
                    "installation_type": "monorepo",
                    "installation_path": "/path/to/test_plugin",
                    "installed_at": "2024-01-01T00:00:00.000000Z",
                    "installed_by": "test_user",
                    "package_source": "https://example.com/repo/plugin",
                    "editable": False,
                }
            ]
        }
        registry_file.write_text(json.dumps(registry_data))
        
        mock_catalog = Mock()
        
        with (
            patch("cpex.tools.cli.inquirer.prompt", return_value={"confirm": True}),
            patch("cpex.tools.cli.console") as mock_console,
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            pytest.raises(click.exceptions.Exit) as exc_info,
        ):
            # Mock the catalog.find method to return None (manifest not found)
            mock_catalog_instance = Mock()
            mock_catalog_instance.find = Mock(return_value=None)
            mock_catalog_class.return_value = mock_catalog_instance
            
            mock_status = Mock()
            mock_status.__enter__ = Mock(return_value=mock_status)
            mock_status.__exit__ = Mock(return_value=False)
            mock_console.status = Mock(return_value=mock_status)
            
            uninstall("test_plugin", mock_catalog)
        
        assert exc_info.value.exit_code == 3  # EXIT_NOT_FOUND
        # When manifest is not found, uninstall should print error and exit
        # So uninstall_package should NOT be called
        mock_catalog_instance.uninstall_package.assert_not_called()
        mock_console.print.assert_any_call(":x: Plugin test_plugin not found in catalog.")



# Made with Bob
