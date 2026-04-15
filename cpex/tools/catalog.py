# -*- coding: utf-8 -*-
"""Location: ./cpex/tools/catalog.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

This module implements the plugin catalog object.
"""

import base64
import importlib.metadata
import importlib.util
import logging
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from github import Auth, Github

from cpex.framework.models import PiPyRepo, PluginManifest, PluginPackageInfo
from cpex.tools.settings import get_catalog_settings

logger = logging.getLogger(__name__)


class PluginCatalog:
    """
    Utility class to initialize the plugin catalog from configured monorepos
    """

    def __init__(self) -> None:
        """Utility for creating the catalog from one or more monorepos."""
        settings = get_catalog_settings()
        self.github_api = os.environ.get("PLUGINS_GITHUB_API", settings.PLUGINS_GITHUB_API)
        self.github_token = os.environ.get("PLUGINS_GITHUB_TOKEN", None)
        self.monorepos = os.environ.get("PLUGINS_REPO_URLS", settings.PLUGINS_REPO_URLS or "").split(",")
        self.plugin_folder = os.environ.get("PLUGINS_FOLDER", settings.PLUGINS_FOLDER)
        self.catalog_folder = os.environ.get("PLUGINS_CATALOG_FOLDER", settings.PLUGINS_CATALOG_FOLDER)
        self.manifests: list[PluginManifest] = []
        self.auth = Auth.Token(self.github_token)
        self.gh = Github(auth=self.auth, base_url=f"https://{self.github_api}", per_page=100)
        self.python_executable = self._get_python_executable()

    def _get_python_executable(self) -> str:
        """Get the Python executable path for the current environment."""
        return sys.executable

    def create_output_folder(self) -> None:
        """Create the plugin catalog output folder."""
        os.makedirs(self.catalog_folder, exist_ok=True)

    def create_folder(self, base_path, rel_path):
        """
        Creates the base_path / rel_path folder to store data in.
        """
        # elements = rel_path.split("/")
        # new_path = Path()
        # for i in range(len(elements)):
        #     new_path = new_path / elements[i]
        relpath = Path(base_path) / rel_path
        # logger.info("relpath: %s", relpath)
        os.makedirs(relpath, exist_ok=True)

    def create_plugin_folder(self, path: str):
        """
        Creates the self.plugin_folder/path folder to store the plugin source in.
        """
        self.create_folder(self.plugin_folder, path)

    def create_catalog_folder(self, path: str):
        """
        Creates the OUTPUT_FOLDER/path folder to store the plugin-manifest.yaml file in.
        """
        self.create_folder(self.catalog_folder, path)
        # elements = path.split("/")
        # new_path = Path()
        # for i in range(len(elements) - 1):
        #     new_path = new_path / elements[i]
        # relpath = Path(OUTPUT_FOLDER / new_path)
        # # logger.info("relpath: %s", relpath)
        # os.makedirs(relpath, exist_ok=True)

    def save_manifest(self, manifest: PluginManifest, path):
        """Save a pypi installed manifest to the plugin catalog.
        args:
             manifest: The plugin manifest to be stored in the catalog
             path: the name of the plugin package that was installed
        """
        relpath = Path(self.catalog_folder)
        relpath = relpath / path
        updated_content = yaml.safe_dump(manifest.model_dump(), default_flow_style=False)
        with open(relpath, "w", encoding="utf-8") as output:
            output.write(updated_content)
            output.flush()

    def save_manifest_content(self, content: str, path, repo_url: httpx.URL):
        """
        write the manifest content to the supplied path relative to the ouptut folder,
        injecting the monorepo.package_source value before saving the file.
        """
        relpath = Path(self.catalog_folder)
        relpath = relpath / path
        repo_path = path.removesuffix(f"/{relpath.name}")
        manifest_data = yaml.safe_load(content)
        package_source = f"{repo_url}#subdirectory={repo_path}"
        manifest_data["monorepo"] = {
            "package_source": f"{package_source}",
            "repo_url": f"{str(repo_url)}",
            "package_folder": f"{repo_path}",
        }
        if "tags" not in manifest_data:
            manifest_data["tags"] = []
        if "name" not in manifest_data:
            manifest_data["name"] = repo_path
        if "default_configs" in manifest_data:
            manifest_data["default_config"] = manifest_data["default_configs"]
            del manifest_data["default_configs"]
            if manifest_data["default_config"] is None:
                manifest_data["default_config"] = {}
        updated_content = yaml.safe_dump(manifest_data, default_flow_style=False)
        with open(relpath, "w", encoding="utf-8") as output:
            output.write(updated_content)
            output.flush()

    def save_content(self, base_path, content: str, path):
        """
        write the content to the supplied path relative to the ouptut folder.
        """
        relpath = Path(base_path)
        relpath = relpath / path
        with open(relpath, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()

    def save_plugin_content(self, content: str, path):
        """
        write the content to the supplied path relative to the plugin folder.
        """
        self.save_content(self.plugin_folder, content, path)

    def save_catalog_content(self, content: str, path):
        """
        write the content to the supplied path relative to the ouptut folder.
        """
        self.save_content(self.catalog_folder, content, path)

    def download_contents(self, git_url: str, headers, path: str, repo_url: httpx.URL):
        """
        Download the contents of the file using the github REST API.
        """
        result = httpx.get(git_url, headers=headers)
        if result.status_code == 200:
            js = result.json()
            b64_content = js["content"]
            content = str(base64.b64decode(b64_content).decode("utf-8"))
            # logger.info("decoded contents:\n%s", content)
            # Extract directory path from full path (remove filename)
            dir_path = str(Path(path).parent) if "/" in path else ""
            if dir_path:
                self.create_catalog_folder(dir_path)
            self.save_manifest_content(content, path, repo_url)
        else:
            logger.error("Failed to download file: %s status_code: %d", git_url, result.status_code)

    def download_file(self, git_url: str, headers) -> str:
        """Download the content of a github file"""
        result = httpx.get(git_url, headers=headers)
        if result.status_code == 200:
            js = result.json()
            b64_content = js["content"]
            content = base64.b64decode(b64_content).decode("utf-8")
            return content
        else:
            logger.error("Failed to download file: %s status_code: %d", git_url, result.status_code)

    def find_and_save_plugin_manifest(self, member: str, name: str, repo_url: httpx.URL, headers) -> PluginManifest:
        """Find the plugin-manifest.yaml relative to the supplied member folder,
        download and save the manifest, updating the monorepo's package_folder, package_source and repo_url attributes
        """
        self.create_output_folder()
        repo_path = repo_url.path.removeprefix("/")
        relpath = Path(self.catalog_folder)
        relpath = relpath / name / "plugin-manifest.yaml"
        self.create_catalog_folder(name)
        params = f"q=repo:{repo_path}+path:{member}+filename:plugin-manifest+extension:yaml&per_page=100"
        r = httpx.get(f"https://{self.github_api}/search/code", params=params, headers=headers)
        logger.info("status code: %d ", r.status_code)
        if r.status_code == 200:
            result = r.json()
            for item in result["items"]:
                # only download yaml files, not the README.md which may also contain references to available_hooks
                if item["name"].endswith(".yaml") and item["name"].startswith("plugin-manifest"):
                    manifest_content = yaml.safe_load(self.download_file(item["git_url"], headers=headers))
                    package_source = f"{repo_url}#subdirectory={member}"
                    manifest_content["name"] = name
                    manifest_content["monorepo"] = {
                        "package_source": f"{package_source}",
                        "repo_url": f"{str(repo_url)}",
                        "package_folder": f"{member}",
                    }
                    if "tags" not in manifest_content:
                        manifest_content["tags"] = []
                    if "default_configs" in manifest_content:
                        manifest_content["default_config"] = manifest_content["default_configs"]
                        del manifest_content["default_configs"]
                        if manifest_content["default_config"] is None:
                            manifest_content["default_config"] = {}
                    updated_content = yaml.safe_dump(manifest_content, default_flow_style=False)
                    with open(relpath, "w", encoding="utf-8") as output:
                        output.write(updated_content)
                        output.flush()
                else:
                    logger.warning("ignoring item[name]=%s.  Not a yaml file.", item["name"])
        else:
            logger.error("Catalog update failed with error code: %d", r.status_code)

    def update_catalog_with_cargo(self) -> None:
        """Update the plugin catalog with the latest available plugins."""
        # Get the list of available plugins from the Cargo registry
        headers = {"accept": "application/vnd.github+json", "authorization": f"Bearer {self.github_token}"}
        self.create_output_folder()
        for repo in self.monorepos:
            repo_url = httpx.URL(repo)
            repo_path = repo_url.path.removeprefix("/")
            cargo_data = tomllib.loads(
                self.download_file(
                    git_url=f"https://{self.github_api}/repos/{repo_path}/contents/Cargo.toml", headers=headers
                )
            )
            for member in cargo_data["workspace"]["members"]:
                project_data = tomllib.loads(
                    self.download_file(
                        git_url=f"https://{self.github_api}/repos/{repo_path}/contents/{member}/pyproject.toml",
                        headers=headers,
                    )
                )
                # project_data.project.name
                self.find_and_save_plugin_manifest(
                    member=member, name=project_data["project"]["name"], repo_url=repo_url, headers=headers
                )

    def load(self) -> None:
        """Load plugin-manifest.yaml files from self.catalog_folder into self.manifests."""
        self.manifests = []
        output_path = Path(self.catalog_folder)

        if not output_path.exists():
            logger.warning("Output folder '%s' does not exist. No manifests to load.", self.catalog_folder)
            return

        # Find all plugin-manifest.yaml files recursively
        manifest_files = list(output_path.rglob("plugin-manifest.yaml"))

        if not manifest_files:
            logger.warning("No plugin-manifest.yaml files found in '%s'.", self.catalog_folder)
            return

        logger.info("Found %d plugin-manifest.yaml file(s) in '%s'.", len(manifest_files), self.catalog_folder)

        for manifest_file in manifest_files:
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    manifest_data = yaml.safe_load(f)

                # Create PluginManifest object from the loaded data
                manifest = PluginManifest(**manifest_data)
                self.manifests.append(manifest)
                logger.info("Loaded manifest from '%s'.", manifest_file)

            except Exception as e:
                logger.error("Failed to load manifest from '%s': %s", manifest_file, str(e))

        logger.info("Successfully loaded %d manifest(s).", len(self.manifests))

    def search(self, plugin_name: str | None) -> Optional[list[PluginManifest]]:
        """Search for a plugin in the catalog"""
        matching: list[PluginManifest] = []
        # lookup the plugin from the catalog's plugin-manifest.yaml
        if (self.manifests is not None) and (len(self.manifests) == 0):
            self.load()
        for manifest in self.manifests:
            if plugin_name is not None:
                if manifest.name.lower().count(plugin_name) > 0:
                    matching.append(manifest)
                elif plugin_name.lower() in manifest.tags:
                    matching.append(manifest)
            else:
                matching.append(manifest)
        return matching if len(matching) > 0 else None

    def install_folder_via_pip(self, manifest: PluginManifest) -> None:
        """
        Runs a pip install using subfolder syntax
        e.g. "git+https://github.com[extra]&subdirectory=folder_name"

        Args:
            manifest: The PluginManifest of the plugin to be installed

        Raises:
            RuntimeError: If package installation fails.
        """
        if manifest.monorepo is None:
            raise RuntimeError("PluginManifest.monorepo can not be None.")
        try:
            # safe_path = package_source.path.strip("/")
            # org = safe_path.split("/")[0]
            # safe_path = safe_path.replace(org, "", 1).lstrip("/")
            repo_url = f"git+{manifest.monorepo.package_source}"
            subprocess.run(
                [self.python_executable, "-m", "pip", "install", repo_url], check=True, capture_output=True, text=True
            )
            logger.info("Successfully installed package: %s", manifest.name)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install {manifest.name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error installing {manifest.name}: {str(e)}") from e

    def _install_package(self, package_name: str, version_constraint: str | None) -> None:
        """Install package from PyPI with proper error handling.

        Args:
            package_name: The PyPI package name to install.
            version_constraint: Optional version constraint (e.g., ">=1.0.0,<2.0.0").

        Raises:
            RuntimeError: If package installation fails.
        """
        try:
            # Validate package name and constraint format
            ppi = PluginPackageInfo(pypi_package=package_name, version_constraint=version_constraint)
            tgt = ppi.pypi_package
            if ppi.version_constraint is not None:
                tgt = f"{tgt}@{ppi.version_constraint}"

            # Use subprocess.run for better error handling
            subprocess.run(
                [self.python_executable, "-m", "pip", "install", tgt], check=True, capture_output=True, text=True
            )
            logger.info("Successfully installed package: %s", package_name)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install {package_name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error installing {package_name}: {str(e)}") from e

    def find_package_path(self, package_name: str) -> Path:
        """Locate installed package directory using importlib.metadata.

        Args:
            package_name: The name of the installed package.

        Returns:
            Path to the package directory.

        Raises:
            RuntimeError: If package cannot be found.
        """
        try:
            # Use importlib.metadata for more reliable package discovery
            for dist in importlib.metadata.distributions():
                if dist.name == package_name or dist.metadata.get("Name") == package_name:
                    if dist.files:
                        # Get the package root from the plugin-manifest.yaml file
                        for afile in dist.files:
                            if afile.name == "plugin-manifest.yaml":
                                located_path = dist.locate_file(afile)
                                package_path = Path(str(located_path)).parent
                                logger.debug("Found package %s at %s", package_name, package_path)
                                return package_path

            # Fallback to importlib.util.find_spec if metadata approach fails
            spec = importlib.util.find_spec(package_name)
            if spec is not None and spec.origin is not None:
                package_path = Path(spec.origin).parent
                logger.debug("Found package %s at %s (via find_spec)", package_name, package_path)
                return package_path

            raise RuntimeError(f"Could not find installed package: {package_name}")

        except Exception as e:
            if isinstance(e, RuntimeError):
                raise
            raise RuntimeError(f"Error locating package {package_name}: {str(e)}") from e

    def _load_manifest_file(self, manifest_path: Path) -> dict[str, Any]:
        """Load and parse plugin-manifest.yaml with validation.

        Args:
            manifest_path: Path to the plugin-manifest.yaml file.

        Returns:
            Parsed manifest data as a dictionary.

        Raises:
            FileNotFoundError: If manifest file doesn't exist.
            RuntimeError: If manifest file cannot be parsed.
        """
        if not manifest_path.exists():
            raise FileNotFoundError(f"plugin-manifest.yaml not found at {manifest_path}")

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = yaml.safe_load(f)

            if not isinstance(manifest_data, dict):
                raise RuntimeError(f"Invalid manifest format: expected dictionary, got {type(manifest_data).__name__}")

            logger.debug("Successfully loaded manifest from %s", manifest_path)
            return manifest_data

        except yaml.YAMLError as e:
            raise RuntimeError(f"Failed to parse manifest YAML: {str(e)}") from e
        except Exception as e:
            raise RuntimeError(f"Error reading manifest file: {str(e)}") from e

    def _normalize_manifest_data(
        self, manifest_data: dict[str, Any], package_name: str, version_constraint: str | None
    ) -> PluginManifest:
        """Transform raw manifest dict into validated PluginManifest model.

        Args:
            manifest_data: Raw manifest dictionary from YAML.
            package_name: The PyPI package name.
            version_constraint: Optional version constraint.

        Returns:
            Validated PluginManifest instance.

        Raises:
            RuntimeError: If manifest validation fails.
        """
        try:
            # Set defaults for optional fields
            manifest_data.setdefault("tags", [])
            manifest_data.setdefault("name", package_name)

            # Handle legacy default_configs field
            if "default_config" not in manifest_data and "default_configs" in manifest_data:
                manifest_data["default_config"] = manifest_data.pop("default_configs") or {}

            # Validate and create manifest
            manifest = PluginManifest(**manifest_data)

            # Ensure package_info is properly set
            if manifest.package_info is None:
                manifest.package_info = PiPyRepo(pypi_package=package_name, version_constraint=version_constraint)
            else:
                manifest.package_info.pypi_package = package_name
                if version_constraint is not None:
                    manifest.package_info.version_constraint = version_constraint

            logger.debug("Successfully normalized manifest for %s", package_name)
            return manifest

        except Exception as e:
            raise RuntimeError(f"Failed to validate manifest for {package_name}: {str(e)}") from e

    def _persist_manifest(self, manifest: PluginManifest, package_name: str) -> None:
        """Save manifest to catalog folder.

        Args:
            manifest: The validated plugin manifest.
            package_name: The package name (used for folder/file naming).

        Raises:
            RuntimeError: If manifest cannot be saved.
        """
        try:
            self.create_catalog_folder(package_name)
            self.save_manifest(manifest, f"{package_name}/plugin-manifest.yaml")
            logger.info("Successfully saved %s package manifest to plugin catalog", package_name)
        except Exception as e:
            raise RuntimeError(f"Failed to save manifest for {package_name}: {str(e)}") from e

    def install_from_pypi(self, plugin_package_name: str, version_constraint: str | None = None) -> PluginManifest:
        """Install Python package from PyPI and load its plugin-manifest.yaml.

        This method performs the following steps:
        1. Installs the package from PyPI
        2. Locates the installed package directory
        3. Loads and parses the plugin-manifest.yaml
        4. Normalizes and validates the manifest data
        5. Persists the manifest to the plugin catalog

        Args:
            plugin_package_name: The name of the package hosted on PyPI.
            version_constraint: Optional version constraint (e.g., ">=1.0.0,<2.0.0").

        Returns:
            The loaded and validated plugin manifest.

        Raises:
            RuntimeError: If any step of the installation process fails.
            FileNotFoundError: If plugin-manifest.yaml is not found in the package.
        """
        # Step 1: Install the package
        self._install_package(plugin_package_name, version_constraint)

        # Step 2: Find the package location where plugin-manifest.yaml resides
        package_path = self.find_package_path(plugin_package_name)

        # Step 3: Load the manifest file
        manifest_path = package_path / "plugin-manifest.yaml"
        manifest_data = self._load_manifest_file(manifest_path)

        # Step 4: Normalize and validate the manifest
        manifest = self._normalize_manifest_data(manifest_data, plugin_package_name, version_constraint)

        # Step 5: Persist to catalog
        self._persist_manifest(manifest, plugin_package_name)

        logger.info("Successfully installed and cataloged %s", plugin_package_name)
        return manifest
