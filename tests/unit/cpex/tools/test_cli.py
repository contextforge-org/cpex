# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/tools/test_cli.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Tests for the cpex CLI bootstrap command and utility functions.
"""

# Standard
import json
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
    list,
    install_from_manifest,
    install,
    search,
    info,
    instance_name_is_unique,
    update_plugins_config_yaml,
)
from cpex.tools.plugin_registry import PluginRegistry
from cpex.framework.models import PluginManifest, Monorepo, Config, PluginConfig, PluginMode

runner = CliRunner()

# cookiecutter is imported locally inside bootstrap(); patch at source module
_CC_PATCH_TARGET = "cookiecutter.main.cookiecutter"


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
        ):
            runner.invoke(app, ["bootstrap", "-d", "/tmp/test_nogit", "--no_input"])
            mock_cc.assert_not_called()
            mock_logger.warning.assert_called_once()


class TestBootstrapErrorHandling:
    """Test bootstrap error handling."""

    def test_logs_exception_on_cookiecutter_error(self):
        with (
            patch(_CC_PATCH_TARGET, side_effect=RuntimeError("template error")),
            patch("cpex.tools.cli.logger") as mock_logger,
        ):
            result = runner.invoke(app, ["bootstrap", "-d", "/tmp/test_err", "--no_input"])
            assert result.exit_code == 0  # error is caught and logged
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

    def test_list_with_no_registry_file(self, tmp_path):
        """Test list when registry file doesn't exist."""
        with (
            patch("cpex.tools.cli.os.environ.get", return_value=str(tmp_path)),
            patch("cpex.tools.cli.logger") as mock_logger,
        ):
            list("all")
            mock_logger.info.assert_called_with("No plugins registered.")

    def test_list_with_existing_plugins(self, tmp_path):
        """Test list with existing plugins in registry."""
        registry_file = tmp_path / "installed-plugins.json"
        registry_data = {
            "plugins": [
                {"name": "test_plugin", "version": "1.0.0", "installation_type": "monorepo"},
                {"name": "another_plugin", "version": "2.0.0", "installation_type": "pypi"},
            ]
        }
        registry_file.write_text(json.dumps(registry_data))

        with (
            patch("cpex.tools.cli.os.environ.get", return_value=str(tmp_path)),
            patch("cpex.tools.cli.logger") as mock_logger,
        ):
            list("all")
            assert mock_logger.info.call_count == 2


class TestUpdatePluginRegistry:
    """Tests for update_plugin_registry() function."""

    def test_creates_new_registry_if_not_exists(self, tmp_path):
        """Test creating a new registry when file doesn't exist."""
        manifest = create_test_manifest()
        
        mock_catalog = Mock()
        mock_catalog.find_package_path = Mock(return_value=Path("/fake/path/to/plugin"))

        with (
            patch.dict("os.environ", {"PLUGIN_REGISTRY_FILE": str(tmp_path)}),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
        ):
            plugin_registry = PluginRegistry()
            plugin_registry.update(manifest, "monorepo", mock_catalog, "test_user")
            registry_file = tmp_path / "installed-plugins.json"
            assert registry_file.exists()

    def test_updates_existing_registry(self, tmp_path):
        """Test updating an existing registry."""
        registry_file = tmp_path / "installed-plugins.json"
        registry_data = {"plugins": []}
        registry_file.write_text(json.dumps(registry_data))

        manifest = create_test_manifest(
            name="new_plugin",
            version="2.0.0",
            kind="external",
            monorepo=Monorepo(package_source="https://example.com/repo#subdirectory=new_plugin", repo_url="https://example.com/repo", package_folder="new_plugin"),
        )
        
        mock_catalog = Mock()
        mock_catalog.find_package_path = Mock(return_value=Path("/fake/path/to/new_plugin"))

        with (
            patch.dict("os.environ", {"PLUGIN_REGISTRY_FILE": str(tmp_path)}),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
        ):
            plugin_registry = PluginRegistry()
            plugin_registry.update(manifest, "monorepo", mock_catalog, "test_user")
            updated_data = json.loads(registry_file.read_text())
            assert len(updated_data["plugins"]) == 1
            assert updated_data["plugins"][0]["name"] == "new_plugin"


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

    def test_install_from_monorepo(self, tmp_path):
        """Test installing from monorepo."""
        manifest = create_test_manifest()

        mock_catalog = Mock()
        mock_catalog.install_folder_via_pip = Mock()
        mock_catalog.find_package_path = Mock(return_value=Path("/fake/path/to/plugin"))

        with (
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.cli.update_plugins_config_yaml"),
        ):
            install_from_manifest(manifest, "monorepo", mock_catalog)
            mock_catalog.install_folder_via_pip.assert_called_once_with(manifest)


class TestInstallFunction:
    """Tests for install() function."""

    def test_install_git_not_implemented(self):
        """Test that git installation raises NotImplementedError."""
        mock_catalog = Mock()
        with pytest.raises(NotImplementedError, match="Git installation is not yet implemented"):
            install("source", "git", mock_catalog)

    def test_install_monorepo_no_plugins_found(self):
        """Test monorepo install when no plugins found."""
        mock_catalog = Mock()
        mock_catalog.search = Mock(return_value=None)

        with patch("cpex.tools.cli.console") as mock_logger:
            install("test_plugin", "monorepo", mock_catalog)
            mock_logger.print.assert_called_with("No matching plugins found.")

    def test_install_monorepo_with_available_plugins(self, tmp_path):
        """Test monorepo install with available plugins."""
        manifest = create_test_manifest()

        mock_catalog = Mock()
        mock_catalog.search = Mock(return_value=[manifest])
        mock_catalog.install_folder_via_pip = Mock()
        mock_catalog.find_package_path = Mock(return_value=Path("/fake/path/to/plugin"))

        with (
            patch("cpex.tools.cli.inquirer.prompt", return_value={"plugins": 0}),
            patch("cpex.tools.cli.Console"),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.cli.update_plugins_config_yaml"),
        ):
            install("test_plugin", "monorepo", mock_catalog)
            mock_catalog.install_folder_via_pip.assert_called_once()

    def test_install_requires_type_parameter(self):
        """Test that install raises ValueError for unsupported type."""
        mock_catalog = Mock()
        with pytest.raises(ValueError, match="Unsupported installation type"):
            install("source", "", mock_catalog)


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

    def test_info_with_no_registry(self, tmp_path):
        """Test info when registry doesn't exist."""
        with (
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.console") as mock_console,
        ):
            info(None)
            mock_console.print.assert_called_with("No plugins found")

    def test_info_list_all_plugins(self, tmp_path):
        """Test info listing all plugins."""
        registry_file = tmp_path / "installed-plugins.json"
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

        with (
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.console") as mock_console,
        ):
            info(None)
            mock_console.print_json.assert_called_once()

    def test_info_search_specific_plugin(self, tmp_path):
        """Test info searching for specific plugin."""
        registry_file = tmp_path / "installed-plugins.json"
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

        with (
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.console") as mock_console,
        ):
            info("test")
            mock_console.print_json.assert_called_once()


class TestPluginCommand:
    """Tests for the plugin() command."""

    def test_plugin_info_command(self, tmp_path):
        """Test plugin info command."""
        with (
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.Console"),
        ):
            result = runner.invoke(app, ["plugin", "info"])
            assert result.exit_code == 0

    def test_plugin_list_command(self, tmp_path):
        """Test plugin list command."""
        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.Console"),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_cargo = Mock()
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "list"])
            assert result.exit_code == 0
            mock_catalog.update_catalog_with_cargo.assert_called_once()

    def test_plugin_search_command(self):
        """Test plugin search command."""
        manifest = create_test_manifest()

        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.Console"),
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_cargo = Mock()
            mock_catalog.search = Mock(return_value=[manifest])
            mock_catalog_class.return_value = mock_catalog

            result = runner.invoke(app, ["plugin", "search", "test"])
            assert result.exit_code == 0
            mock_catalog.search.assert_called_once_with("test")

    def test_plugin_install_command(self, tmp_path):
        """Test plugin install command."""
        manifest = create_test_manifest()

        with (
            patch("cpex.tools.cli.PluginCatalog") as mock_catalog_class,
            patch("cpex.tools.cli.Console"),
            patch("cpex.tools.cli.inquirer.prompt", return_value={"plugins": 0}),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FOLDER", tmp_path),
            patch("cpex.tools.cli.DEFAULT_PLUGIN_REGISTRY_FILE", "installed-plugins.json"),
            patch("cpex.tools.cli.git_user_name", return_value="test_user"),
            patch("cpex.tools.cli.update_plugins_config_yaml"),
        ):
            mock_catalog = Mock()
            mock_catalog.update_catalog_with_cargo = Mock()
            mock_catalog.search = Mock(return_value=[manifest])
            mock_catalog.install_folder_via_pip = Mock()
            mock_catalog.find_package_path = Mock(return_value=Path("/fake/path/to/plugin"))
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
