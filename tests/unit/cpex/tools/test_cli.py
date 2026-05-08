# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/tools/test_cli.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Tests for the cpex CLI bootstrap command and utility functions.
"""

# Standard
from pathlib import Path
from unittest.mock import MagicMock, patch

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
)

runner = CliRunner()

# cookiecutter is imported locally inside bootstrap(); patch at source module
_CC_PATCH_TARGET = "cookiecutter.main.cookiecutter"


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
