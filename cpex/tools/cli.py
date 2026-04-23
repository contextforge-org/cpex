# -*- coding: utf-8 -*-
"""Location: ./cpex/tools/cli.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

mcpplugins CLI ─ command line tools for authoring and packaging plugins
This module is exposed as a **console-script** via:

    [project.scripts]
    mcpplugins = "cpex.tools.cli:main"

so that a user can simply type `mcpplugins ...` to use the CLI.

Features
─────────
* bootstrap: Creates a new plugin project from template                                                           │
* install: Installs plugins into a Python environment                                                           │
* package: Builds an MCP server to serve plugins as tools

Typical usage
─────────────
```console
$ mcpplugins --help
```
"""

# Standard
import json
import logging
import os
import shutil
import subprocess  # nosec B404 # Safe: Used only for git commands with hardcoded args

# import sys
from pathlib import Path
from typing import List, Optional

import inquirer
import typer
from rich.console import Console
from typing_extensions import Annotated

# First-Party
from cpex.framework.loader.config import ConfigLoader, ConfigSaver
from cpex.framework.models import (
    Config,
    PluginManifest,
    PluginMode,
)
from cpex.framework.settings import settings
from cpex.tools.catalog import PluginCatalog

# Third-Party
from cpex.tools.plugin_registry import PluginRegistry

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
LOCAL_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
DEFAULT_TEMPLATE_URL = "https://github.com/contextforge-org/contextforge-plugins-framework.git"
DEFAULT_AUTHOR_NAME = "<changeme>"
DEFAULT_AUTHOR_EMAIL = "<changeme>"
DEFAULT_PROJECT_DIR = Path("./.")
DEFAULT_INSTALL_MANIFEST = Path("plugins/install.yaml")
DEFAULT_PLUGIN_REGISTRY_FOLDER = Path(os.environ.get("PLUGIN_REGISTRY_FILE", "data"))
DEFAULT_PLUGIN_REGISTRY_FILE = "installed-plugins.json"
DEFAULT_IMAGE_TAG = "contextforge-plugin:latest"  # TBD: add plugin name and version
DEFAULT_IMAGE_BUILDER = "docker"
DEFAULT_BUILD_CONTEXT = "."
DEFAULT_CONTAINERFILE_PATH = Path("docker/Dockerfile")
DEFAULT_VCS_REF = "main"
DEFAULT_INSTALLER = "uv pip install"

# ---------------------------------------------------------------------------
# CLI (overridable via environment variables)
# ---------------------------------------------------------------------------

markup_mode = settings.cli_markup_mode or typer.core.DEFAULT_MARKUP_MODE
app = typer.Typer(
    help="Command line tools for authoring and packaging plugins.",
    add_completion=settings.cli_completion,
    rich_markup_mode=None if markup_mode == "disabled" else markup_mode,
)

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def command_exists(command_name: str) -> bool:
    """Check if a given command-line utility exists and is executable.

    Args:
        command_name: The name of the command to check (e.g., "ls", "git").

    Returns:
        True if the command exists and is executable, False otherwise.
    """
    return shutil.which(command_name) is not None


def git_user_name() -> str:
    """Return the current git user name from the environment.

    Returns:
        The git user name configured in the user's environment.

    Examples:
        >>> user_name = git_user_name()
        >>> isinstance(user_name, str)
        True
    """
    try:
        res = subprocess.run(["git", "config", "user.name"], stdout=subprocess.PIPE, check=False)  # nosec B607 B603 # Safe: hardcoded git command
        return res.stdout.strip().decode() if not res.returncode else DEFAULT_AUTHOR_NAME
    except Exception:
        return DEFAULT_AUTHOR_NAME


def git_user_email() -> str:
    """Return the current git user email from the environment.

    Returns:
        The git user email configured in the user's environment.

    Examples:
        >>> user_name = git_user_email()
        >>> isinstance(user_name, str)
        True
    """
    try:
        res = subprocess.run(["git", "config", "user.email"], stdout=subprocess.PIPE, check=False)  # nosec B607 B603 # Safe: hardcoded git command
        return res.stdout.strip().decode() if not res.returncode else DEFAULT_AUTHOR_EMAIL
    except Exception:
        return DEFAULT_AUTHOR_EMAIL


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@app.command(help="Creates a new plugin project from template.")
def bootstrap(
    destination: Annotated[
        Path, typer.Option("--destination", "-d", help="The directory in which to bootstrap the plugin project.")
    ] = DEFAULT_PROJECT_DIR,
    template_url: Annotated[
        str,
        typer.Option(
            "--template_url",
            "-u",
            help="The URL to the plugins cookiecutter template. Overrides local templates when provided.",
        ),
    ] = None,
    template_type: Annotated[
        str, typer.Option("--template_type", "-t", help="Plugin template type: native or external.")
    ] = "native",
    vcs_ref: Annotated[
        str,
        typer.Option("--vcs_ref", "-r", help="The version control system tag/branch/commit to use for the template."),
    ] = DEFAULT_VCS_REF,
    no_input: Annotated[bool, typer.Option("--no_input", help="Use defaults without prompting.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry_run", help="Run but do not make any changes.")] = False,
) -> None:
    """Boostrap a new plugin project from a template.

    Args:
        destination: The directory in which to bootstrap the plugin project.
        template_url: The URL to the plugins cookiecutter template.
        template_type: Plugin template type (native, external or isolated).
        vcs_ref: The version control system tag/branch/commit to use for the template.
        no_input: Use defaults without prompting.
        dry_run: Run but do not make any changes.

    Raises:
        Exit: If cookiecutter is not installed.
    """
    try:
        # Third-Party
        from cookiecutter.main import cookiecutter  # pylint: disable=import-outside-toplevel
    except ImportError:
        logger.error("cookiecutter is not installed. Install with: pip install mcp-contextforge-gateway[templating]")
        raise typer.Exit(1)

    if dry_run:
        source = template_url if template_url is not None else str(LOCAL_TEMPLATES_DIR / template_type)
        logger.info(
            "Dry run: would create plugin project at %s from template %s (type=%s)",
            destination,
            source,
            template_type,
        )
        return

    try:
        output_dir = str(destination.parent) if destination.parent != destination else "."
        extra_context = {
            "plugin_slug": destination.name,
            "author": git_user_name(),
            "email": git_user_email(),
        }

        # Explicit URL overrides local templates; otherwise prefer local
        local_template_dir = LOCAL_TEMPLATES_DIR / template_type
        use_remote = template_url is not None

        if use_remote:
            if not command_exists("git"):
                logger.error("git is required to fetch remote templates but was not found.")
                raise typer.Exit(1)
            cookiecutter(
                template=template_url,
                checkout=vcs_ref,
                directory=f"cpex/templates/{template_type}",
                output_dir=output_dir,
                no_input=no_input,
                extra_context=extra_context,
            )
        elif local_template_dir.is_dir():
            cookiecutter(
                template=str(local_template_dir),
                output_dir=output_dir,
                no_input=no_input,
                extra_context=extra_context,
            )
        elif command_exists("git"):
            cookiecutter(
                template=DEFAULT_TEMPLATE_URL,
                checkout=vcs_ref,
                directory=f"cpex/templates/{template_type}",
                output_dir=output_dir,
                no_input=no_input,
                extra_context=extra_context,
            )
        else:
            logger.warning("No local templates found and git is not available to fetch remote template.")
    except (SystemExit, typer.Exit):
        raise
    except Exception:
        logger.exception("An error was caught while copying template.")


def list(type: str) -> None:
    """List the installed plugins
    Args:
    type (str): The type of plugins to list. Can be "native" or "external".

    Raises:
    typer.Exit: If the type is not "native" or "external".
    """
    pr = PluginRegistry()

    registered_plugins = pr.registry.plugins

    if registered_plugins:
        for plug_in in registered_plugins:
            logger.info(
                "name: %s version: %s installation type: %s",
                plug_in.name,
                plug_in.version,
                plug_in.installation_type,
            )
    else:
        logger.info("No plugins registered.")


def instance_name_is_unique(config: Config, suggested_instance_name) -> bool:
    """See if the instance name already exists in the plugins/config.yaml"""
    if config.plugins is not None:
        for a_plugin in config.plugins:
            if a_plugin.name == suggested_instance_name:
                return False
    return True


def update_plugins_config_yaml(manifest: PluginManifest):
    """
    Update the plugins/config.yaml file with the new plugin manifest.

    Args:
        manifest (PluginManifest): The plugin manifest to be added to the config.yaml file.
    Returns:
        bool: True if the update was successful, False otherwise.
    """
    plugin_configs: Config = ConfigLoader.load_config(settings.config_file)
    suggested_name = manifest.suggest_instance_name()
    ctr = 1
    while not instance_name_is_unique(plugin_configs, suggested_instance_name=suggested_name):
        suggested_name = manifest.suggest_instance_name() + "_" + str(ctr)
        ctr += 1

    accepted_name = suggested_name
    # TODO: prompt to confirm mode, priority etc and accepted name?
    plugin_config = manifest.create_instance_config(
        instance_name=accepted_name, mode=PluginMode.SEQUENTIAL, priority=100
    )
    if plugin_configs.plugins is None:
        plugin_configs.plugins = []
    plugin_configs.plugins.append(plugin_config)
    # now serialize the config
    ConfigSaver.save_config(plugin_configs, settings.config_file)


def remove_from_plugins_config_yaml(manifest: PluginManifest) -> bool:
    """
    Remove a plugin from the plugins/config.yaml file.

    Args:
        plugin_name: The name of the plugin to remove from the config.

    Returns:
        bool: True if the plugin was found and removed, False otherwise.
    """
    try:
        plugin_configs: Config = ConfigLoader.load_config(settings.config_file)

        if plugin_configs.plugins is None:
            return False

        initial_count = len(plugin_configs.plugins)
        # Need to match by manifest.kind or if plugin.name starts with manifest.name
        # e.g. if it is an external plugin or a venv plugin then kind will match many plugin configurations in config.yaml
        plugin_configs.plugins = [
            p for p in plugin_configs.plugins if p.kind != manifest.kind and p.name.count(manifest.name) == 0
        ]
        if len(plugin_configs.plugins) < initial_count:
            ConfigSaver.save_config(plugin_configs, settings.config_file)
            return True

        return False
    except Exception as e:
        logger.error("Error removing plugin from config: %s", str(e))
        return False


def install_from_manifest(manifest: PluginManifest, installation_type: str, catalog: PluginCatalog):
    """
    Given a plugin manifest, download the plugin and register it in the plugin registry.

    Args:
        manifest (PluginManifest): The plugin manifest to be installed.
        installation_type (str): The type of installation, either "monorepo" or "pypi".
        catalog (PluginCatalog): The plugin catalog to be used for installation.
    Returns:
        None: This function does not return anything.
    """

    # download the plugin to the plugins folder
    if installation_type == "monorepo":
        logger.info("installation type: %s", installation_type)
        plugin_path = catalog.install_folder_via_pip(manifest)
        plugin_registry: PluginRegistry = PluginRegistry()
        # add the newly downloaded plugin to the registry
        plugin_registry.update(
            manifest=manifest, installation_type=installation_type, catalog=catalog, git_user_name=git_user_name(), plugin_path=plugin_path
        )
        update_plugins_config_yaml(manifest)


def select_plugin_from_catalog(available_plugins: List[PluginManifest]) -> Optional[PluginManifest]:
    """Select a plugin from a list of available plugins using an interactive prompt.

    Args:
        available_plugins: List of available plugin manifests to choose from.

    Returns:
        The selected PluginManifest, or None if no selection was made.
    """
    if not available_plugins:
        return None

    # Build choices list with plugin information
    choices = []
    for index, plug_in in enumerate(available_plugins):
        installation_type = (
            "monorepo" if plug_in.monorepo is not None else "pypi" if plug_in.package_info is not None else "local"
        )
        choice = f"{index} name: {plug_in.name} version: {plug_in.version} installation type: {installation_type}"
        choices.append((choice, index))

    # Prompt user to select a plugin
    questions = [
        inquirer.List(
            "plugins",
            message="Which plugin would you like to install?",
            choices=choices,
        ),
    ]
    answers = inquirer.prompt(questions)

    if not answers:
        return None

    logger.info(json.dumps(answers))
    selected_index = int(answers["plugins"])
    selected_plugin = available_plugins[selected_index]

    # Display selected plugin information
    installation_type = (
        "monorepo"
        if selected_plugin.monorepo is not None
        else "pypi"
        if selected_plugin.package_info is not None
        else "local"
    )
    console.print(
        "name: ",
        selected_plugin.name,
        "Version: ",
        selected_plugin.version,
        "type: ",
        installation_type,
    )

    return selected_plugin


def _parse_pypi_source(source: str) -> tuple[str, Optional[str]]:
    """Parse PyPI source string to extract package name and version constraint.

    Args:
        source: PyPI package source string, optionally with version (e.g., "package@>=1.0.0").

    Returns:
        Tuple of (package_name, version_constraint).
    """
    parts = source.split("@", 1)
    package_name = parts[0]
    version_constraint = parts[1] if len(parts) > 1 else None
    return package_name, version_constraint


def _finalize_installation(manifest: PluginManifest, install_type: str, catalog: PluginCatalog, plugin_path: Path | None = None):
    """Common finalization steps for plugin installation.

    Args:
        manifest: The plugin manifest to finalize.
        install_type: The type of installation (e.g., "pypi", "monorepo").
        catalog: The plugin catalog.
    """
    plugin_registry = PluginRegistry()
    plugin_registry.update(
        manifest=manifest, installation_type=install_type, catalog=catalog, git_user_name=git_user_name(), plugin_path=plugin_path
    )
    update_plugins_config_yaml(manifest=manifest)


def _install_from_local(source: str, catalog: PluginCatalog, use_test: bool = False):
    """Handle local-based installation (not yet implemented).

    Args:
        source: local path.
        catalog: The plugin catalog.

    Raises:
        NotImplementedError: local installation is not yet supported.
    """
    raise NotImplementedError("Local installation is not yet implemented")


def _install_from_git(source: str, catalog: PluginCatalog, use_test: bool = False):
    """Handle git-based installation (not yet implemented).

    Args:
        source: Git repository URL or path.
        catalog: The plugin catalog.

    Raises:
        NotImplementedError: Git installation is not yet supported.
    """
    raise NotImplementedError("Git installation is not yet implemented")


def _install_from_monorepo(source: str, catalog: PluginCatalog, use_test: bool = False):
    """Handle monorepo-based installation.

    Args:
        source: Plugin name or search term in the monorepo.
        catalog: The plugin catalog.
    """
    logger.info("Trying to install from git monorepo: %s", source)
    available_plugins = catalog.search(source)

    if not available_plugins:
        console.print("No matching plugins found.")
        return

    selected_plugin = select_plugin_from_catalog(available_plugins)
    if not selected_plugin:
        return

    with console.status(f"Installing plugin {selected_plugin.name}...", spinner="dots"):
        install_from_manifest(selected_plugin, "monorepo", catalog=catalog)

    console.print(f":white_heavy_check_mark: {selected_plugin.name} installation complete.")


def _install_from_pypi(source: str, catalog: PluginCatalog, use_test: bool = False):
    """Handle PyPI-based installation.

    Args:
        source: PyPI package name, optionally with version constraint (e.g., "package@>=1.0.0").
        catalog: The plugin catalog.
    """
    logger.info("Trying to install from pypi package %s", source)

    # Parse version constraint
    package_name, version_constraint = _parse_pypi_source(source)

    with console.status(f"Installing plugin {package_name} via pypi", spinner="dots"):
        manifest, plugin_path = catalog.install_from_pypi(
            plugin_package_name=package_name, version_constraint=version_constraint, use_pytest=use_test
        )

    if manifest is None:
        console.print(f":x: Failed to install {package_name}")
        return

    _finalize_installation(manifest, "pypi", catalog, plugin_path)
    console.print(f":white_heavy_check_mark: {package_name} installation complete.")


def install(source: str, install_type: str | None, catalog: PluginCatalog):
    """Install a plugin from its associated source.

    Args:
        source: The source of the plugin (package name, repo URL, or search term).
        install_type: The type of installation ("git", "monorepo", or "pypi").
        catalog: The catalog of plugins.

    Raises:
        ValueError: If install_type is not supported.
        NotImplementedError: If the installation type is not yet implemented.
    """
    if install_type is None:
        install_type = "monorepo"

    handlers = {
        "git": _install_from_git,
        "monorepo": _install_from_monorepo,
        "pypi": _install_from_pypi,
        "test-pypi": _install_from_pypi,
        "local": _install_from_local,
    }

    handler = handlers.get(install_type)
    if handler is None:
        raise ValueError(f"Unsupported installation type: {install_type}. Must be one of: {', '.join(handlers.keys())}")

    handler(source, catalog, use_test=True if install_type == "test-pypi" else False)


def search(plugin_name: str | None, catalog: PluginCatalog):
    """Search for a plugin in the catalog
    Args:
        plugin_name (str | None): The name of the plugin to search for.
        catalog (PluginCatalog): The catalog to search in.
    Returns:
        list[Plugin]: A list of plugins that match the search criteria.
    """
    # lookup the plugin from the catalog's plugin-manifest.yaml
    with console.status("Searching for available plugins ...", spinner="dots"):
        available_plugins = catalog.search(plugin_name)
    if available_plugins:
        console.log("Available plugins:")
        for plug_in in available_plugins:
            msg = f"name: {plug_in.name} version: {plug_in.version} installation type: {'monorepo' if plug_in.monorepo is not None else 'pypi' if plug_in.package_info is not None else 'local'}"
            console.log(msg)
    else:
        console.log("No plugins found.")


def info(plugin_name: str | None):
    """Search for or list all installed plugins

    Args:
        plugin_name (str | None): The name of the plugin to search for.
        If None, list all installed plugins.

        Returns:
            list[Plugin]: A list of plugins that match the search criteria.
    """
    registry = PluginRegistry().registry

    found = 0
    for plug_in in registry.plugins:
        if plugin_name is None:
            console.print_json(json.dumps(plug_in.model_dump()))
            # console.print(yaml.dump(plug_in.model_dump(), default_flow_style=False))
            found += 1
        else:
            if (
                plug_in.name.lower().count(plugin_name.lower()) > 0
                or plug_in.kind.lower().count(plugin_name.lower()) > 0
            ):
                console.print_json(json.dumps(plug_in.model_dump()))
                # console.print(yaml.dump(plug_in.model_dump()))
                found += 1
    if found == 0:
        console.print("No plugins found")


def uninstall(plugin_name: str, catalog: PluginCatalog) -> None:
    """Uninstall a plugin.

    Args:
        plugin_name: The name of the plugin to uninstall.
        catalog: The plugin catalog.
    """
    # Get plugin registry to find the installed plugin
    plugin_registry = PluginRegistry()

    # Find the plugin in the registry
    installed_plugin = None
    for plugin in plugin_registry.registry.plugins:
        if plugin.name == plugin_name:
            installed_plugin = plugin
            break

    if installed_plugin is None:
        console.print(f":x: Plugin '{plugin_name}' is not installed.")
        return

    # Confirm uninstallation
    console.print(f"Found plugin: {installed_plugin.name} (version {installed_plugin.version})")
    console.print(f"Installation type: {installed_plugin.installation_type}")
    console.print(f"Installation path: {installed_plugin.installation_path}")

    questions = [
        inquirer.Confirm(
            "confirm",
            message=f"Are you sure you want to uninstall '{plugin_name}'?",
            default=False,
        ),
    ]
    answers = inquirer.prompt(questions)

    if not answers or not answers["confirm"]:
        console.print("Uninstall cancelled.")
        return

    try:
        with console.status(f"Uninstalling plugin {plugin_name}...", spinner="dots"):
            # Uninstall the package using pip
            catalog.uninstall_package(plugin_name)

            # Remove from plugin registry
            plugin_registry.remove(plugin_name)
            # retrieve the manifest so we can match on kind value
            catalog = PluginCatalog()
            manifest = catalog.find(plugin_name)
            # Remove from plugins/config.yaml
            if manifest:
                remove_from_plugins_config_yaml(manifest)
            else:
                console.print(f"Plugin {plugin_name} not found in plugins config.yaml.")

        console.print(f":white_heavy_check_mark: {plugin_name} uninstalled successfully.")

    except Exception as e:
        console.print(f":x: Failed to uninstall {plugin_name}: {str(e)}")
        logger.error("Uninstall error: %s", str(e), exc_info=True)


@app.command(
    help="List, search, install or uninstall plugins.\n\n"
    "\ndefault install type is monorepo\n"
    "Examples:\n"
    "python cpex/tools/cli.py plugin info pii\n"
    "python cpex/tools/cli.py plugin search pii\n"
    "python cpex/tools/cli.py plugin --type monorepo search pii\n"
    "python cpex/tools/cli.py plugin --type monorepo install cpex-pii-filter\n"
    'python cpex/tools/cli.py plugin --type pypi install "ExamplePlugin@>=0.1.0"\n'
    'python cpex/tools/cli.py plugin --type test-pypi install "cpex-plugin-test@>=0.1.1"\n'
    "python cpex/tools/cli.py plugin uninstall cpex-pii-filter"
)
def plugin(
    cmd_action: str = typer.Argument(None, help="One of: list|info|install|search|uninstall"),
    source: str | None = typer.Argument(None, help="The pypi, git, or local folder where the plugin resides"),
    install_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help="The types of plugins to list.  One of: monorepo|pypi|test-pypi|git|local  Defaults to monorepo if unspecified.",
        ),
    ] = None,
) -> None:
    """Lists installed plugins"""
    if cmd_action == "info":
        return info(source)

    # For uninstall, we don't need to update the catalog
    if cmd_action == "uninstall":
        if source is None:
            console.print(":x: Please specify a plugin name to uninstall.")
            return
        pc = PluginCatalog()
        return uninstall(source, catalog=pc)
    if cmd_action == "install" and source is not None:
        registry = PluginRegistry()
        if registry.has(source):
            console.print(f"Plugin {source} is already installed.")
            return

    # update the catalog before proceeding with install etc.
    pc = PluginCatalog()
    # optimized github search REST api takes ~14s to search & download all manifests
    console.log("Update catalog")
    with console.status("Updating catalog...", spinner="dots"):
        rc = pc.update_catalog_with_pyproject()
        if rc is False:
            console.log("Catalog update completed.")
        else:
            console.log("❌ Catalog update failed.")

    if cmd_action == "list":
        return list(install_type)
    if cmd_action == "install" and source is not None:
        return install(source, install_type, catalog=pc)
    if cmd_action == "search":
        return search(source, catalog=pc)


@app.callback()
def callback() -> None:  # pragma: no cover
    """This function exists to force 'bootstrap' to be a subcommand."""


def main() -> None:  # noqa: D401 - imperative mood is fine here
    """Entry point for the *mcpplugins* console script.

    Processes command line arguments, handles version requests, and forwards
    all other arguments to Uvicorn with sensible defaults injected.

    Environment Variables:
        PLUGINS_CLI_COMPLETION: Enable auto-completion for plugins CLI (default: false)
        PLUGINS_CLI_MARKUP_MODE: Set markup mode for plugins CLI (default: rich)
            Valid options:
                rich: use rich markup
                markdown: allow markdown in help strings
                disabled: disable markup
            If unset (commented out), uses "rich" if rich is detected, otherwise disables it.
    """
    app()


if __name__ == "__main__":  # pragma: no cover - executed only when run directly
    # logging.basicConfig(
    #     level=logging.INFO,
    #     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    #     stream=sys.stderr,  # Log to stderr to keep stdout clean for coordination
    # )
    main()
