# -*- coding: utf-8 -*-
"""Location: ./cpex/tools/catalog.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

This module implements the plugin catalog object.
"""

import base64
import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import uuid
import zipfile
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from github import Auth, Github
from packaging.version import InvalidVersion, Version

from cpex.framework.models import (
    GitRepo,
    PluginManifest,
    PluginPackageInfo,
    PluginVersionInfo,
    PluginVersionRegistry,
    PyPiRepo,
)
from cpex.framework.utils import find_package_path
from cpex.tools.integrity import (
    IntegrityVerificationError,
    fetch_pypi_package_hashes,
    find_matching_hash,
    verify_package_integrity,
)
from cpex.tools.settings import get_catalog_settings

logger = logging.getLogger(__name__)


class PluginCatalog:
    """
    Utility class to initialize the plugin catalog from configured monorepos
    """

    def __init__(self) -> None:
        """Utility for creating the catalog from one or more monorepos."""
        settings = get_catalog_settings()
        self.github_api = settings.GITHUB_API
        self.github_token = settings.GITHUB_TOKEN
        self.monorepos = settings.REPO_URLS.split(",")
        self.plugin_folder = settings.FOLDER
        self.catalog_folder = settings.CATALOG_FOLDER
        self.manifests: list[PluginManifest] = []
        # Only create Auth.Token if a token is provided to avoid errors with None
        self.auth = Auth.Token(self.github_token) if self.github_token else None
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
        relpath = Path(base_path) / rel_path
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

    def save_manifest(self, manifest: PluginManifest, path):
        """Save a pypi installed manifest to the plugin catalog.
        args:
             manifest: The plugin manifest to be stored in the catalog
             path: the name of the plugin package that was installed
        """
        relpath = Path(self.catalog_folder) / path
        updated_content = yaml.safe_dump(manifest.model_dump(), default_flow_style=False)
        relpath.write_text(updated_content, encoding="utf-8")

    def _ver(self, version_str: str) -> Version:
        """
        Parse a version string into a Version object.

        Args:
            version_str: Version string to parse (e.g., "1.0.0", "2.0.0rc1")

        Returns:
            Version object. Returns Version("0") if parsing fails.
        """
        try:
            return Version(version_str)
        except InvalidVersion:
            logger.debug("Could not parse version %r as PEP 440; treating as lowest", version_str)
            return Version("0")

    def update_plugin_version_registry(self, manifest: PluginManifest, relpath: Path):
        """
        Update the plugin version registry with the given manifest.
        args:
            manifest: The plugin manifest to be stored in the catalog
            relpath: the relative path of the plugin package that was installed
        """
        plugin_version = PluginVersionInfo(
            version=manifest.version,
            manifest_file=str(relpath),
            released=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        )

        file_path = Path(self.catalog_folder) / manifest.name / "versions.json"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Load or create registry
        if file_path.exists():
            with file_path.open("r") as f:
                plugin_version_registry = PluginVersionRegistry(**json.load(f))
        else:
            plugin_version_registry = PluginVersionRegistry(versions=[])

        # Check if version already exists (avoid duplicates)
        version_exists = any(pv.version == plugin_version.version for pv in plugin_version_registry.versions)

        # Add new version if not duplicate
        if not version_exists:
            plugin_version_registry.versions.append(plugin_version)

        # Recalculate latest version from all versions
        if plugin_version_registry.versions:
            plugin_version_registry.latest = max(plugin_version_registry.versions, key=lambda pv: self._ver(pv.version))

        # Write the updated version registry to the file
        file_path.write_text(
            json.dumps(plugin_version_registry.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )

    def save_manifest_content(self, content: str, path, repo_url: httpx.URL):
        """
        write the manifest content to the supplied path relative to the ouptut folder,
        injecting the monorepo.package_source value before saving the file.
        """
        relpath = Path(self.catalog_folder) / path
        repo_path = path.removesuffix(f"/{relpath.name}")

        manifest_data = yaml.safe_load(content)

        # Set name if not present (different from find_and_save_plugin_manifest which always sets it)
        if "name" not in manifest_data:
            manifest_data["name"] = repo_path

        # Use shared transformation logic
        manifest_data = self._transform_manifest_data(manifest_data, manifest_data["name"], repo_path, repo_url)

        updated_content = yaml.safe_dump(manifest_data, default_flow_style=False)
        relpath.write_text(updated_content, encoding="utf-8")
        pm: PluginManifest = PluginManifest(**manifest_data)
        self.update_plugin_version_registry(pm, relpath)

    def save_content(self, base_path, content: str, path):
        """
        write the content to the supplied path relative to the ouptut folder.
        """
        relpath = Path(base_path) / path
        relpath.write_text(content, encoding="utf-8")

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
        result = httpx.get(git_url, headers=headers, timeout=30.0)
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

    def download_file(self, repo_path: str, item: dict, headers, gh_repo) -> str | None:
        """Download the content of a github file

           Args:
               repo_path: Repository path (e.g., 'owner/repo')
               item: Dictionary containing the path of the file to download
               headers: GitHub API headers
        Returns:
            Content of the file as a string or None if the file could not be downloaded
        """
        # Get the repository using PyGithub
        try:
            file_content = gh_repo.get_contents(item["path"])
            content = file_content.decoded_content.decode("utf-8")
            return content
        except Exception as e:
            logger.error("Failed to download file: %s error: %s", item["path"], str(e))

    def _search_github_code_for_versions_json(self, repo_path: str, member: str | None, headers) -> list[dict] | None:
        """Search GitHub for plugin-manifest*.yaml files in a specific path using PyGithub API.

        Args:
            repo_path: Repository path (e.g., 'owner/repo')
            member: Directory path within the repository
            headers: HTTP headers for authentication (kept for compatibility but not used)

        Returns:
            List of search result items as dicts with 'name' and 'git_url' keys, or None if request failed
        """
        try:
            # Build search query for PyGithub - search for files starting with plugin-manifest and ending with .yaml
            # Note: GitHub search doesn't support wildcards in filename, so we search broadly and filter results
            if member is not None:
                query = f"repo:{repo_path} path:{member} filename:versions extension:json"
            else:
                query = f"repo:{repo_path} filename:versions extension:json"
            # Use PyGithub's search_code method
            search_results = self.gh.search_code(query=query)

            logger.info("Found %d versions.json files in %s/%s", search_results.totalCount, repo_path, member)

            # Convert PyGithub ContentFile objects to dict format compatible with existing code
            items = []
            for content_file in search_results:
                # Filter to only include files that start with "plugin-manifest" and end with ".yaml"
                if content_file.name.startswith("versions") and content_file.name.endswith(".json"):
                    items.append(
                        {
                            "name": content_file.name,
                            "path": content_file.path,
                            "git_url": content_file.git_url,
                            "html_url": content_file.html_url,
                        }
                    )

            return items

        except Exception as e:
            logger.error("Catalog update failed with error: %s", str(e))
            return None

    def _search_github_code(self, repo_path: str, member: str | None, headers) -> list[dict] | None:
        """Search GitHub for plugin-manifest*.yaml files in a specific path using PyGithub API.

        Args:
            repo_path: Repository path (e.g., 'owner/repo')
            member: Directory path within the repository
            headers: HTTP headers for authentication (kept for compatibility but not used)

        Returns:
            List of search result items as dicts with 'name' and 'git_url' keys, or None if request failed
        """
        try:
            # Build search query for PyGithub - search for files starting with plugin-manifest and ending with .yaml
            # Note: GitHub search doesn't support wildcards in filename, so we search broadly and filter results
            if member is not None:
                query = f"repo:{repo_path} path:{member} extension:yaml"
            else:
                query = f"repo:{repo_path} extension:yaml"
            # Use PyGithub's search_code method
            search_results = self.gh.search_code(query=query)

            logger.info("Found %d plugin-manifest files in %s/%s", search_results.totalCount, repo_path, member)

            # Convert PyGithub ContentFile objects to dict format compatible with existing code
            items = []
            for content_file in search_results:
                # Filter to only include files that start with "plugin-manifest" and end with ".yaml"
                if content_file.name.startswith("plugin-manifest") and content_file.name.endswith(".yaml"):
                    items.append(
                        {
                            "name": content_file.name,
                            "path": content_file.path,
                            "git_url": content_file.git_url,
                            "html_url": content_file.html_url,
                        }
                    )

            return items

        except Exception as e:
            logger.error("Catalog update failed with error: %s", str(e))
            return None

    def _transform_manifest_data(
        self, manifest_content: dict, name: str, member: str | None, repo_url: httpx.URL
    ) -> dict:
        """Apply standard transformations to manifest data.

        Args:
            manifest_content: Raw manifest data from YAML
            name: Plugin name
            member: Directory path within the repository
            repo_url: Repository URL

        Returns:
            Transformed manifest data with monorepo metadata
        """
        if member is None:
            package_source = str(repo_url)
        else:
            package_source = f"{repo_url}#subdirectory={member}"

        manifest_content["name"] = name
        manifest_content.setdefault("tags", [])
        manifest_content["monorepo"] = {
            "package_source": package_source,
            "repo_url": str(repo_url),
            "package_folder": member if member is not None else "",
        }

        # Normalize default_configs -> default_config
        if "default_configs" in manifest_content:
            manifest_content["default_config"] = manifest_content.pop("default_configs") or {}

        return manifest_content

    def _process_manifest_item(
        self,
        item: dict,
        name: str,
        member: str,
        repo_url: httpx.URL,
        headers,
        relpath: Path,
        repo_path: str,
        gh_repo,
    ) -> bool:
        """Process a single manifest search result item.

        Args:
            item: Search result item from GitHub API
            name: Plugin name
            member: Directory path within the repository
            repo_url: Repository URL
            headers: HTTP headers for authentication
            relpath: Path where manifest should be saved

        Returns:
            True if manifest was successfully processed and saved, False otherwise
        """
        # Only download yaml files, not the README.md which may also contain references to available_hooks
        if not (item["name"].endswith(".yaml") and item["name"].startswith("plugin-manifest")):
            logger.warning("ignoring item[name]=%s. Not a yaml file.", item["name"])
            return False

        # manifest_data = self.download_file(repo_path=repo_path, git_url=item["git_url"], headers=headers)
        manifest_data = self.download_file(repo_path=repo_path, item=item, headers=headers, gh_repo=gh_repo)
        if manifest_data is None:
            logger.error("Failed to download plugin-manifest from %s", member)
            return False

        manifest_content = yaml.safe_load(manifest_data)
        manifest_content = self._transform_manifest_data(manifest_content, name, member, repo_url)

        updated_content = yaml.safe_dump(manifest_content, default_flow_style=False)
        relpath.write_text(updated_content, encoding="utf-8")
        pm: PluginManifest = PluginManifest(**manifest_content)
        self.update_plugin_version_registry(pm, relpath)

        return True

    def _process_version_item(
        self, item: dict, member: str, name: str, repo_url: httpx.URL, headers, relpath, repo_path, gh_repo
    ) -> None:
        """Find plugin-versions.json files relative to the supplied member folder,
        download and save the manifest, updating the monorepo's package_folder, package_source and repo_url attributes
        Args:
            member: Directory path within the repository
            name: Plugin name
            repo_url: Repository URL
            headers: HTTP headers for authentication
        """
        self.create_output_folder()
        self.create_catalog_folder(name)
        version_data = self.download_file(repo_path=repo_path, item=item, headers=headers, gh_repo=gh_repo)
        if version_data is None:
            logger.error("Skipping version item for %s (%s) — download failed", name, item.get("path"))
            return
        relpath.write_text(version_data, encoding="utf-8")

    def find_and_save_plugin_versions_json(self, member: str, name: str, repo_url: httpx.URL, headers, gh_repo) -> None:
        """Find plugin-versions.json files relative to the supplied member folder,
        download and save the manifest, updating the monorepo's package_folder, package_source and repo_url attributes
        Args:
           member: Directory path within the repository
           name: Plugin name
           repo_url: Repository URL
           headers: HTTP headers for authentication
           gh_repo: GitHub repository object
        """
        self.create_output_folder()
        self.create_catalog_folder(name)

        repo_path = repo_url.path.removeprefix("/")
        items: list[dict[Any, Any]] | None = self._search_github_code_for_versions_json(
            repo_path=repo_path, member=member, headers=headers
        )
        if items is None:
            return None
        for item in items:
            relpath = Path(self.catalog_folder) / name / item["name"]
            self._process_version_item(item, member, name, repo_url, headers, relpath, repo_path, gh_repo)

    def find_and_save_plugin_manifest(
        self, member: str, name: str, repo_url: httpx.URL, headers, gh_repo
    ) -> PluginManifest | None:
        """Find plugin-manifest*.yaml files relative to the supplied member folder,
        download and save the manifest, updating the monorepo's package_folder, package_source and repo_url attributes

        Args:
            member: Directory path within the repository
            name: Plugin name
            repo_url: Repository URL
            headers: HTTP headers for authentication

        Returns:
            None (could be extended to return PluginManifest if needed)
        """
        self.create_output_folder()
        self.create_catalog_folder(name)

        repo_path = repo_url.path.removeprefix("/")

        items = self._search_github_code(repo_path, member, headers)
        if items is None:
            return None

        for item in items:
            # Use the actual filename from the search result
            relpath = Path(self.catalog_folder) / name / item["name"]
            self._process_manifest_item(item, name, member, repo_url, headers, relpath, repo_path, gh_repo)

        return None

    def _process_pyproject(self, gh_repo, item, repo_url: httpx.URL, headers) -> None:
        """Process a single pyproject.toml file.

        Args:
            gh_repo: PyGithub Repository object
            item: Search result item containing pyproject.toml path
            repo_url: Repository URL
            headers: HTTP headers for authentication

        Raises:
            Exception: If processing fails (caller should handle)
        """
        # Get the directory path (remove filename)
        if item.path.find("/") == -1:
            member = None
        else:
            member = item.path.removesuffix("/" + item.name)

        # Download pyproject.toml content using PyGithub
        file_content = gh_repo.get_contents(item.path)
        pyproject_data = file_content.decoded_content.decode("utf-8")

        if pyproject_data is None:
            logger.warning("Failed to download pyproject.toml from %s", item.path)
            return

        # Parse the pyproject.toml
        project_data = tomllib.loads(pyproject_data)

        # Find and save the versions.json file
        self.find_and_save_plugin_versions_json(
            member=member, name=project_data["project"]["name"], repo_url=repo_url, headers=headers, gh_repo=gh_repo
        )

        # Find and save the plugin manifest
        self.find_and_save_plugin_manifest(
            member=member, name=project_data["project"]["name"], repo_url=repo_url, headers=headers, gh_repo=gh_repo
        )

    def update_catalog_with_pyproject(self) -> bool:
        """Update the catalog with the pyproject.toml file using PyGithub API."""
        if self.github_token is None:
            logger.error("No GitHub token set")
            return True

        headers = {"accept": "application/vnd.github+json", "authorization": f"Bearer {self.github_token}"}
        self.create_output_folder()

        # Cache repositories to avoid repeated API calls
        repo_cache: dict[str, Any] = {}

        for repo in self.monorepos:
            repo_url = httpx.URL(repo.strip())
            repo_path = repo_url.path.removeprefix("/")

            try:
                # Get repository using PyGithub (with caching)
                if repo_path not in repo_cache:
                    repo_cache[repo_path] = self.gh.get_repo(repo_path)
                gh_repo = repo_cache[repo_path]

                # Search for pyproject.toml files using PyGithub search
                query = f"repo:{repo_path} filename:pyproject extension:toml"
                search_results = self.gh.search_code(query=query)

                logger.info("Found %d pyproject.toml files in %s", search_results.totalCount, repo_path)

                for item in search_results:
                    if "pyproject.toml" in item.name:
                        try:
                            self._process_pyproject(gh_repo, item, repo_url, headers)
                        except Exception as e:
                            logger.error("Error processing pyproject.toml at %s: %s", item.path, str(e))
                            continue

            except Exception as e:
                logger.error("Error accessing repository %s: %s", repo_path, str(e))
                continue

        return False

    def load(self) -> None:
        """Load plugin-manifest.yaml files from self.catalog_folder into self.manifests."""
        self.manifests = []
        output_path = Path(self.catalog_folder)

        if not output_path.exists():
            logger.warning("Output folder '%s' does not exist. No manifests to load.", self.catalog_folder)
            return

        # Find all plugin-manifest.yaml files recursively
        manifest_files = list(output_path.rglob("plugin-manifest*.yaml"))

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
                if manifest.name.lower().count(plugin_name.lower()) > 0:
                    matching.append(manifest)
                elif plugin_name.lower() in manifest.tags:
                    matching.append(manifest)
            else:
                matching.append(manifest)
        return matching if len(matching) > 0 else None

    def find(self, plugin_name: str) -> Optional[PluginManifest]:
        """Find a plugin in the catalog
        Args:
           plugin_name: The name of the plugin to find
        Returns:
            The manifest of the plugin if found, None otherwise
        """
        # lookup the plugin from the catalog's plugin-manifest.yaml
        if (self.manifests is not None) and (len(self.manifests) == 0):
            self.load()
        for manifest in self.manifests:
            if manifest.name.lower() == plugin_name.lower():
                return manifest
        return None

    def install_folder_via_pip(self, manifest: PluginManifest, verify_integrity: bool = True) -> Path | None:
        """
        Runs a pip install using subfolder syntax for monorepo plugins.
        For isolated_venv plugins, checks manifest kind BEFORE installing to avoid dependency conflicts.
        e.g. "git+https://github.com[extra]&subdirectory=folder_name"

        Args:
            manifest: The PluginManifest of the plugin to be installed
            verify_integrity: Whether to compute and log package hash for verification

        Raises:
            RuntimeError: If package installation fails.
        """
        if manifest.monorepo is None:
            raise RuntimeError("PluginManifest.monorepo can not be None.")
        try:
            repo_url = f"git+{manifest.monorepo.package_source}"

            plugin_path = None
            # Check manifest kind BEFORE installing
            if manifest.kind == "isolated_venv":
                logger.info("Detected isolated_venv plugin from monorepo: %s", manifest.name)
                # Install the package to make it available for venv initialization
                package_path = self._download_monorepo_folder_to_temp(
                    repo_url, manifest.name, verify_integrity=verify_integrity
                )
                plugin_path = self._initialize_isolated_venv(manifest, package_path)
                logger.info("Isolated venv initialized. Plugin will be auto-installed via requirements.txt")
            else:
                # For non-isolated plugins, install normally into CLI's venv
                logger.info("Installing non-isolated plugin from monorepo: %s", manifest.name)
                subprocess.run(
                    [self.python_executable, "-m", "pip", "install", repo_url],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                logger.info("Successfully installed package: %s", manifest.name)
            return plugin_path

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install {manifest.name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error installing {manifest.name}: {str(e)}") from e

    def _install_package(self, package_name: str, version_constraint: str | None, use_test: bool = False) -> None:
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
                tgt = f"{tgt}{ppi.version_constraint}"
            if use_test:
                subprocess.run(
                    [
                        self.python_executable,
                        "-m",
                        "pip",
                        "install",
                        "--index-url",
                        "https://test.pypi.org/simple/",
                        tgt,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            else:
                subprocess.run(
                    [self.python_executable, "-m", "pip", "install", tgt],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            logger.info("Successfully installed package: %s", package_name)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install {package_name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error installing {package_name}: {str(e)}") from e

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
                manifest.package_info = PyPiRepo(pypi_package=package_name, version_constraint=version_constraint)
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

    @staticmethod
    def _safe_zip_extract(zip_ref: zipfile.ZipFile, extract_dir: Path) -> None:
        """Extract a zip archive, rejecting members whose paths escape extract_dir."""
        base = extract_dir.resolve()
        for info in zip_ref.infolist():
            name = info.filename
            if os.path.isabs(name):
                raise RuntimeError(f"Unsafe path in archive: {name}")
            target = (base / name).resolve()
            if not target.is_relative_to(base):
                raise RuntimeError(f"Unsafe path in archive: {name}")
        zip_ref.extractall(extract_dir)

    def _extract_package_archive(self, package_file: Path, extract_dir: Path) -> None:
        """Extract a package archive (zip, tar.gz, wheel, etc.) to a directory.

        Args:
            package_file: Path to the archive file.
            extract_dir: Directory to extract to.

        Raises:
            RuntimeError: If the archive format is unsupported or contains unsafe paths.
        """
        if package_file.suffix == ".whl" or package_file.name.endswith(".whl"):
            with zipfile.ZipFile(package_file, "r") as zip_ref:
                self._safe_zip_extract(zip_ref, extract_dir)
        elif package_file.suffix == ".zip" or package_file.name.endswith(".zip"):
            with zipfile.ZipFile(package_file, "r") as zip_ref:
                self._safe_zip_extract(zip_ref, extract_dir)
        elif package_file.suffix in [".gz", ".bz2"] or ".tar" in package_file.name:
            with tarfile.open(package_file, "r:*") as tar_ref:
                tar_ref.extractall(extract_dir, filter="data")
        else:
            raise RuntimeError(f"Unsupported package format: {package_file}")

    def _download_monorepo_folder_to_temp(
        self, repo_url: str, package_name: str, verify_integrity: bool = True
    ) -> Path:
        """Download monorepo folder to temporary directory.

        Args:
            repo_url: The URL of the monorepo.
            package_name: Name used in error messages.
            verify_integrity: Whether to compute and log package hash for verification.

        Returns:
            Path to the extracted package directory. Caller is responsible for cleanup.
        """
        tmpid = uuid.uuid4()
        temp_dir = Path(tempfile.mkdtemp(prefix=f"cpex_plugin_{tmpid}_"))
        try:
            logger.info("Downloading monorepo folder to %s", temp_dir)

            download_args = [
                self.python_executable,
                "-m",
                "pip",
                "download",
                "--no-deps",
                "--dest",
                str(temp_dir),
            ]
            download_args.append(repo_url)

            subprocess.run(download_args, check=True, capture_output=True, text=True, timeout=600)

            downloaded_files = list(temp_dir.glob("*"))
            if not downloaded_files:
                raise RuntimeError(f"No files downloaded for {package_name}")
            package_file = downloaded_files[0]

            # Compute and log hash for integrity verification
            if verify_integrity:
                try:
                    from cpex.tools.integrity import compute_file_hash

                    package_hash = compute_file_hash(package_file)
                    logger.info(
                        "Package integrity hash for %s (%s): SHA256=%s", package_name, package_file.name, package_hash
                    )
                    logger.info("Store this hash for future verification or to detect tampering")
                except Exception as e:
                    logger.warning("Failed to compute package hash: %s", str(e))

            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir()

            self._extract_package_archive(package_file, extract_dir)

            logger.info("Downloaded and extracted %s to %s", package_name, extract_dir)
            return extract_dir

        except subprocess.CalledProcessError as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to download {package_name}: {e.stderr}") from e
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Unexpected error downloading {package_name}: {str(e)}") from e

    def _download_package_to_temp(
        self, package_name: str, version_constraint: str | None, use_test: bool = False, verify_integrity: bool = True
    ) -> Path:
        """Download package to a temporary directory without installing it.

        Args:
            package_name: The PyPI package name to download.
            version_constraint: Optional version constraint.
            use_test: Whether to use test.pypi.org.
            verify_integrity: Whether to verify package integrity using SHA256 hashes.

        Returns:
            Path to the downloaded package directory.

        Raises:
            RuntimeError: If download fails.
            IntegrityVerificationError: If hash verification fails.
        """

        try:
            # Create temporary directory
            temp_dir = Path(tempfile.mkdtemp(prefix=f"cpex_plugin_{package_name}_"))

            # Validate package name and constraint format
            ppi = PluginPackageInfo(pypi_package=package_name, version_constraint=version_constraint)
            tgt = ppi.pypi_package
            if ppi.version_constraint is not None:
                tgt = f"{tgt}{ppi.version_constraint}"

            # Fetch expected hashes from PyPI before downloading (if verification enabled)
            expected_hashes = {}
            if verify_integrity:
                try:
                    logger.info("Fetching package hashes from PyPI for %s", package_name)
                    # Extract version from constraint if available, otherwise fetch latest
                    version_to_fetch = None
                    if version_constraint:
                        # Try to extract exact version from constraint (e.g., "==1.0.0" -> "1.0.0")
                        import re

                        version_match = re.search(r"==\s*([0-9.]+)", version_constraint)
                        if version_match:
                            version_to_fetch = version_match.group(1)

                    expected_hashes = fetch_pypi_package_hashes(
                        package_name=package_name, version=version_to_fetch, use_test=use_test
                    )
                    if expected_hashes:
                        logger.info("Retrieved hashes for %d distribution files", len(expected_hashes))
                    else:
                        logger.warning("No hashes available from PyPI for %s", package_name)
                except Exception as e:
                    logger.warning("Failed to fetch hashes from PyPI: %s. Proceeding without verification.", str(e))
                    expected_hashes = {}

            # Download package without installing
            download_args = [
                self.python_executable,
                "-m",
                "pip",
                "download",
                "--no-deps",  # Don't download dependencies
                "--dest",
                str(temp_dir),
            ]

            if use_test:
                download_args.extend(["--index-url", "https://test.pypi.org/simple/"])

            download_args.append(tgt)

            subprocess.run(download_args, check=True, capture_output=True, text=True, timeout=600)

            # Find the downloaded file
            downloaded_files = list(temp_dir.glob("*"))
            if not downloaded_files:
                raise RuntimeError(f"No files downloaded for {package_name}")

            package_file = downloaded_files[0]

            # Verify package integrity if hashes are available
            if verify_integrity and expected_hashes:
                expected_hash = find_matching_hash(package_file, expected_hashes, package_name)
                if expected_hash:
                    logger.info("Verifying integrity of %s", package_file.name)
                    verify_package_integrity(
                        file_path=package_file, expected_hash=expected_hash, package_name=package_name, strict=True
                    )
                else:
                    logger.warning("No matching hash found for %s. Proceeding without verification.", package_file.name)

            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir()

            # Extract the package using common helper
            self._extract_package_archive(package_file, extract_dir)

            logger.info("Downloaded and extracted %s to %s", package_name, extract_dir)
            return extract_dir

        except IntegrityVerificationError:
            # Re-raise integrity errors without wrapping
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise
        except subprocess.CalledProcessError as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to download {package_name}: {e.stderr}") from e
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Unexpected error downloading {package_name}: {str(e)}") from e

    def _find_manifest_in_extracted_package(self, extract_dir: Path, package_name: str) -> Path:
        """Find plugin-manifest.yaml in extracted package.

        Args:
            extract_dir: Directory where package was extracted.
            package_name: Name of the package.

        Returns:
            Path to plugin-manifest.yaml.

        Raises:
            FileNotFoundError: If manifest not found.
        """
        # Search for plugin-manifest.yaml in the extracted directory
        manifest_files = list(extract_dir.rglob("plugin-manifest.yaml"))

        if not manifest_files:
            raise FileNotFoundError(f"plugin-manifest.yaml not found in {package_name} package")

        # Return the first manifest found
        return manifest_files[0]

    def _find_requirements_in_extracted_package(
        self, extract_dir: Path, package_name: str, requirements_file: str
    ) -> Path:
        """Find requirements file in extracted package with path traversal protection.

        Args:
            extract_dir: Directory where package was extracted.
            package_name: Name of the package.
            requirements_file: Name of the requirements file to find.

        Returns:
            Path to requirements file.

        Raises:
            FileNotFoundError: If requirements file not found.
            ValueError: If requirements_file contains path traversal attempts.
        """
        # Validate requirements_file to prevent path traversal attacks
        # Normalize the path and check for suspicious patterns
        normalized_file = os.path.normpath(requirements_file)

        # Check for path traversal attempts (../, absolute paths, etc.)
        if normalized_file.startswith("..") or os.path.isabs(normalized_file):
            raise ValueError(
                f"Invalid requirements file path '{requirements_file}': path traversal attempts are not allowed"
            )

        # Additional check: ensure no path separators that could escape the directory
        if normalized_file != requirements_file.replace("\\", "/").strip("/"):
            raise ValueError(
                f"Invalid requirements file path '{requirements_file}': suspicious path components detected"
            )

        # Search for requirements file in the extracted directory
        manifest_files = list(extract_dir.rglob(requirements_file))

        if not manifest_files:
            raise FileNotFoundError(f"requirements file {requirements_file} not found in {package_name} package")

        # Verify the found file is actually within extract_dir (defense in depth)
        found_file = manifest_files[0]
        try:
            found_file.resolve().relative_to(extract_dir.resolve())
        except ValueError as e:
            raise ValueError(
                f"Security violation: requirements file '{found_file}' is outside the package directory"
            ) from e

        # Return the first manifest found
        return found_file

    def _initialize_isolated_venv(self, manifest: PluginManifest, package_path: Path) -> Path:
        """Initialize isolated venv for a plugin without installing it into the CLI's venv.

        This method creates and initializes the target venv for isolated_venv plugins,
        allowing the plugin's requirements.txt to self-reference and auto-install the plugin.

        Args:
            manifest: The plugin manifest.
            package_path: Path to the installed package directory.

        Raises:
            RuntimeError: If venv initialization fails.
        """
        try:
            # Import here to avoid circular dependency
            from cpex.framework.isolated.client import IsolatedVenvPlugin
            from cpex.framework.models import PluginMode

            logger.info("Initializing isolated venv for plugin: %s", manifest.name)

            # Create a temporary PluginConfig from the manifest
            plugin_config = manifest.create_instance_config(
                instance_name=manifest.name,
                mode=PluginMode.SEQUENTIAL,  # Mode doesn't matter for initialization
                priority=100,
            )

            # Create an IsolatedVenvPlugin instance
            isolated_plugin = IsolatedVenvPlugin(
                config=plugin_config,
                plugin_dirs=[str(self.plugin_folder)],
            )
            # TODO: sec - prevent path traversal on user supplied requirements file path.
            requirements_file = manifest.default_config.get("requirements_file", "requirements.txt")
            source_path = self._find_requirements_in_extracted_package(package_path, manifest.name, requirements_file)
            shutil.copy(source_path, isolated_plugin.plugin_path / requirements_file)
            # Initialize the venv (this will create venv and install requirements)
            import asyncio
            import concurrent.futures

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is None:
                asyncio.run(isolated_plugin.initialize())
            else:
                # Called from within a running event loop (e.g. Jupyter, async CLI).
                # Run in a thread to avoid "asyncio.run cannot be called from a running event loop".
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    ex.submit(asyncio.run, isolated_plugin.initialize()).result()

            logger.info("Successfully initialized isolated venv for %s", manifest.name)

            return isolated_plugin.plugin_path

        except Exception as e:
            raise RuntimeError(f"Failed to initialize isolated venv for {manifest.name}: {str(e)}") from e

    def _find_and_load_versions_json(
        self, manifest: PluginManifest, plugin_path: Path | None, plugin_package_name: str
    ) -> Path | None:
        """Find and load versions.json file from installed package.

        Args:
            manifest: The plugin manifest
            plugin_path: Path to the installed plugin (None for isolated_venv before installation)
            plugin_package_name: The package name

        This method handles two cases:
        1. For non-isolated plugins: Uses the plugin_path directly
        2. For isolated_venv plugins: Runs a subprocess in the venv to find the package path
        """
        try:
            actual_plugin_path = plugin_path

            # For isolated_venv plugins, we need to find the package path within the venv
            if manifest.kind == "isolated_venv" and plugin_path:
                # The plugin_path for isolated_venv is the venv directory
                # We need to find where the package is actually installed within it
                venv_path = plugin_path
                python_executable = self._get_venv_python_executable(venv_path / ".venv")

                # Script receives the package name via sys.argv to avoid f-string injection.
                find_package_script = """
import sys
import importlib.metadata
from pathlib import Path

package_name = sys.argv[1]
try:
    for dist in importlib.metadata.distributions():
        if dist.name == package_name or dist.metadata.get("Name") == package_name:
            if dist.files:
                for afile in dist.files:
                    if afile.name == "versions.json":
                        located_path = dist.locate_file(afile)
                        print(str(Path(located_path).parent))
                        sys.exit(0)
    print("NOT_FOUND", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
"""

                # Execute the script in the isolated venv
                result = subprocess.run(
                    [python_executable, "-c", find_package_script, plugin_package_name],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.returncode == 0 and result.stdout.strip():
                    actual_plugin_path = Path(result.stdout.strip())
                    logger.debug("Found package path in isolated venv: %s", actual_plugin_path)
                else:
                    logger.warning(
                        "Could not find versions.json in isolated venv for %s: %s",
                        plugin_package_name,
                        result.stderr,
                    )
                    return

            # Now load the versions.json file if it exists
            if actual_plugin_path:
                versions_json_path = actual_plugin_path / "versions.json"
                if versions_json_path.exists():
                    logger.info("Found versions.json at %s", versions_json_path)
                    with open(versions_json_path, "r", encoding="utf8") as f:
                        versions_data = json.load(f)
                    # Save to catalog
                    catalog_versions_path = Path(self.catalog_folder) / manifest.name / "versions.json"
                    catalog_versions_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(catalog_versions_path, "w", encoding="utf8") as f:
                        json.dump(versions_data, f, indent=2)
                    logger.info("Saved versions.json to catalog: %s", catalog_versions_path)
                    return actual_plugin_path
                else:
                    logger.debug("No versions.json found at %s", versions_json_path)

        except Exception as e:
            logger.warning("Failed to find/load versions.json for %s: %s", plugin_package_name, e)

    def _get_venv_python_executable(self, venv_path: Path) -> str:
        """Get the Python executable path for a virtual environment.

        Args:
            venv_path: Path to the virtual environment directory

        Returns:
            Path to the Python executable as a string
        """
        if sys.platform == "win32":
            python_exe = venv_path / "Scripts" / "python.exe"
        else:
            python_exe = venv_path / "bin" / "python"

        if not python_exe.exists():
            raise FileNotFoundError(f"Python executable not found at {python_exe}")

        return str(python_exe)

    def _handle_plugin_installation(
        self, manifest: PluginManifest, package_path: Path, install_command: list[str] | None = None
    ) -> Path | None:
        """Handle plugin installation based on its kind (isolated_venv or regular).

        Args:
            manifest: The plugin manifest.
            package_path: Path to the package source.
            install_command: Optional custom install command for non-isolated plugins.
                           If None, no installation is performed for non-isolated plugins.

        Returns:
            Path to the installed plugin, or None if not applicable.

        Raises:
            RuntimeError: If installation fails.
        """
        plugin_path = None

        if manifest.kind == "isolated_venv":
            logger.info("Detected isolated_venv plugin: %s", manifest.name)
            plugin_path = self._initialize_isolated_venv(manifest, package_path)
            logger.info("Isolated venv initialized. Plugin auto-installed via requirements.txt")
        else:
            # For non-isolated plugins, install if command provided
            if install_command:
                logger.info("Installing non-isolated plugin: %s", manifest.name)
                subprocess.run(
                    install_command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                logger.info("Successfully installed package: %s", manifest.name)

        return plugin_path

    def _finalize_plugin_installation(
        self, manifest: PluginManifest, plugin_path: Path | None, package_name: str
    ) -> Path | None:
        """Perform post-installation steps: persist manifest, find versions.json, update registry.

        Args:
            manifest: The plugin manifest.
            plugin_path: Path to the installed plugin (plugins/{manifest.name} directory).
            package_name: Name of the package.

        Returns:
            The actual plugin path from versions.json (inside .venv for isolated plugins),
            or plugin_path if versions.json not found.
        """
        # Step 1: Persist to catalog
        self._persist_manifest(manifest, package_name)

        # Step 2: Find and save versions.json if available
        # This returns the actual package location (inside .venv for isolated plugins)
        actual_plugin_path = self._find_and_load_versions_json(manifest, plugin_path, package_name)

        # Step 3: Update the plugin version registry
        # IMPORTANT: Use plugin_path (not actual_plugin_path) for the registry
        # plugin_path is the plugins/{manifest.name} directory
        # actual_plugin_path is the location inside .venv (for isolated plugins)
        if plugin_path is not None:
            self.update_plugin_version_registry(manifest=manifest, relpath=plugin_path)

        logger.info("Successfully installed and cataloged %s", package_name)

        # Return actual_plugin_path for reference (may be inside .venv)
        return actual_plugin_path if actual_plugin_path is not None else plugin_path

    def install_from_pypi(
        self,
        plugin_package_name: str,
        version_constraint: str | None = None,
        use_pytest: bool = False,
        verify_integrity: bool = True,
    ) -> tuple[PluginManifest, Path | None]:
        """Install Python package from PyPI and load its plugin-manifest.yaml.

        This method performs the following steps:
        1. Downloads package to check manifest (without installing for isolated_venv)
        2. Loads and parses the plugin-manifest.yaml
        3. Normalizes and validates the manifest data
        4. For isolated_venv plugins: initializes the target venv (plugin auto-installs via requirements.txt)
        5. For other plugins: installs normally into CLI's venv
        6. Persists the manifest to the plugin catalog
        7. Finds and saves versions.json if available
        8. Updates the plugin version registry

        Args:
            plugin_package_name: The name of the package hosted on PyPI.
            version_constraint: Optional version constraint (e.g., ">=1.0.0,<2.0.0").
            use_pytest: Whether to use test.pypi.org instead of pypi.org.
            verify_integrity: Whether to verify package integrity using SHA256 hashes from PyPI.

        Returns:
            The loaded and validated plugin manifest.

        Raises:
            RuntimeError: If any step of the installation process fails.
            FileNotFoundError: If plugin-manifest.yaml is not found in the package.
            IntegrityVerificationError: If package hash verification fails.
        """

        # Step 1: Download package to temporary location to read manifest (with integrity verification)
        temp_extract_dir = self._download_package_to_temp(
            plugin_package_name, version_constraint, use_pytest, verify_integrity=verify_integrity
        )

        try:
            # Step 2: Find and load the manifest file
            manifest_path = self._find_manifest_in_extracted_package(temp_extract_dir, plugin_package_name)
            manifest_data = self._load_manifest_file(manifest_path)

            # Step 3: Normalize and validate the manifest
            manifest = self._normalize_manifest_data(manifest_data, plugin_package_name, version_constraint)

            package_path = manifest_path.parent

            # Step 4: Handle installation based on plugin kind
            plugin_path = self._handle_plugin_installation(
                manifest,
                package_path,
                install_command=None,  # Will install separately for non-isolated
            )

            # For non-isolated plugins, install via pip and find package path
            if manifest.kind != "isolated_venv":
                self._install_package(plugin_package_name, version_constraint, use_pytest)
                plugin_path = find_package_path(plugin_package_name)

            # Step 5-7: Finalize installation (persist, versions.json, registry)
            plugin_path = self._finalize_plugin_installation(manifest, plugin_path, plugin_package_name)

            return manifest, plugin_path

        finally:
            # Clean up temporary directory
            if temp_extract_dir.exists():
                shutil.rmtree(temp_extract_dir.parent)

    def install_from_git(self, url: str, verify_integrity: bool = True) -> tuple[PluginManifest, Path | None]:
        """Install Python package from Git repository and load its plugin-manifest.yaml.

        This method performs the following steps:
        1. Parses the Git URL to extract package name and repository details
        2. Downloads package to temporary location to read manifest
        3. Loads and parses the plugin-manifest.yaml
        4. Normalizes and validates the manifest data
        5. For isolated_venv plugins: initializes the target venv and installs via pip into isolated venv
        6. For other plugins: installs via pip into current venv
        7. Persists the manifest to the plugin catalog
        8. Finds and saves versions.json if available
        9. Updates the plugin version registry

        Args:
            url: Git repository URL in one of these formats:
                - MyProject @ git+ssh://git@git.example.com/MyProject
                - MyProject @ git+https://git.example.com/MyProject
                - MyProject @ git+https://git.example.com/MyProject@master
            verify_integrity: Whether to compute and log package hash for verification

        Returns:
            Tuple of (PluginManifest, Path to plugin or None)

        Raises:
            ValueError: If URL format is invalid.
            RuntimeError: If any step of the installation process fails.
            FileNotFoundError: If plugin-manifest.yaml is not found in the package.
        """
        # Step 1: Parse the Git URL
        # Expected format: "PackageName@git+protocol://repo_url[@branch/tag/commit]"
        if " @ " not in url:
            raise ValueError(
                f"Invalid Git URL format: '{url}'. Expected format: 'PackageName @ git+protocol://repo_url'"
            )

        package_name, git_spec = url.split(" @ ", 1)
        package_name = package_name.strip()

        # Remove 'git+' prefix and extract protocol
        if not git_spec.startswith("git+"):
            raise ValueError(f"Git URL must start with 'git+': '{git_spec}'")

        git_url = git_spec[4:]  # Remove 'git+' prefix

        # Extract branch/tag/commit if specified (after @)
        git_branch_tag_commit = None
        if "@" in git_url and not git_url.startswith("git@"):
            # Split on the last @ to handle git@host:repo@branch format
            parts = git_url.rsplit("@", 1)
            if len(parts) == 2:
                git_url, git_branch_tag_commit = parts

        # Validate using PluginPackageInfo
        try:
            PluginPackageInfo(
                git_repository=git_url,
                git_branch_tag_commit=git_branch_tag_commit,
            )
        except Exception as e:
            raise ValueError(f"Invalid Git repository URL: {str(e)}") from e

        logger.info("Installing package '%s' from Git repository: %s", package_name, git_url)
        if git_branch_tag_commit:
            logger.info("Using branch/tag/commit: %s", git_branch_tag_commit)

        # Step 2: Download package to temporary location to read manifest
        # We'll use pip download to get the package without installing it first
        temp_dir = Path(tempfile.mkdtemp(prefix="cpex_git_"))
        temp_extract_dir = temp_dir / "extracted"
        temp_extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Construct the full git URL for pip
            pip_git_url = f"git+{git_url}"
            if git_branch_tag_commit:
                pip_git_url = f"{pip_git_url}@{git_branch_tag_commit}"

            # Download the package using pip
            logger.info("Downloading package from Git repository...")
            subprocess.run(
                [
                    self.python_executable,
                    "-m",
                    "pip",
                    "download",
                    "--no-deps",
                    "--dest",
                    str(temp_dir),
                    pip_git_url,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Find the downloaded archive
            archives = list(temp_dir.glob("*.tar.gz")) + list(temp_dir.glob("*.zip")) + list(temp_dir.glob("*.whl"))
            if not archives:
                raise RuntimeError(f"No package archive found after downloading from {git_url}")

            archive_path = archives[0]
            logger.info("Downloaded archive: %s", archive_path.name)

            # Compute and log hash for integrity verification
            if verify_integrity:
                try:
                    from cpex.tools.integrity import compute_file_hash

                    package_hash = compute_file_hash(archive_path)
                    logger.info(
                        "Package integrity hash for %s (%s): SHA256=%s", package_name, archive_path.name, package_hash
                    )
                    logger.info("Store this hash for future verification or to detect tampering")
                except Exception as e:
                    logger.warning("Failed to compute package hash: %s", str(e))

            # Extract the archive using common helper
            self._extract_package_archive(archive_path, temp_extract_dir)

            # Step 3: Find and load the manifest file
            manifest_path = self._find_manifest_in_extracted_package(temp_extract_dir, package_name)
            manifest_data = self._load_manifest_file(manifest_path)

            # Step 4: Normalize and validate the manifest
            manifest = self._normalize_manifest_data(manifest_data, package_name, None)

            # Update the manifest with the git repo information
            git_repo: GitRepo = GitRepo(
                git_repository=git_url,
                git_branch_tag_commit=git_branch_tag_commit,
            )
            manifest.git_repo = git_repo

            package_path = manifest_path.parent
            install_url = f"{package_name} @ {git_spec}"

            # Step 5: Handle installation based on plugin kind
            plugin_path = self._handle_plugin_installation(
                manifest,
                package_path,
                install_command=None,  # Will install separately
            )

            # Install the package from git
            if manifest.kind == "isolated_venv":
                # Install into isolated venv
                if plugin_path is None:
                    raise RuntimeError(f"Failed to initialize isolated venv for {manifest.name}")
                venv_python = self._get_venv_python_executable(plugin_path / ".venv")
                logger.info("Installing package into isolated venv: %s", install_url)
                subprocess.run(
                    [venv_python, "-m", "pip", "install", install_url],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                logger.info("Successfully installed into isolated venv")
            else:
                # Install into current venv
                subprocess.run(
                    [self.python_executable, "-m", "pip", "install", install_url],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                plugin_path = find_package_path(package_name)

            # Step 6-8: Finalize installation (persist, versions.json, registry)
            plugin_path = self._finalize_plugin_installation(manifest, plugin_path, package_name)

            return manifest, plugin_path

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to install {package_name} from Git: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error installing {package_name} from Git: {str(e)}") from e
        finally:
            # Clean up temporary directory
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    def uninstall_package(self, package_name: str, manifest: PluginManifest) -> bool:
        """Uninstall a Python package using pip.

        Args:
            package_name: The name of the package to uninstall.

        Returns:
            True if uninstallation was successful, False otherwise.

        Raises:
            RuntimeError: If the uninstallation process fails.
        """
        try:
            if manifest.kind == "isolated_venv":
                # Import here to avoid circular dependency
                from cpex.framework.isolated.client import IsolatedVenvPlugin
                from cpex.framework.models import PluginMode

                # Create a temporary PluginConfig from the manifest
                plugin_config = manifest.create_instance_config(
                    instance_name=manifest.name,
                    mode=PluginMode.SEQUENTIAL,
                    priority=100,
                )

                # Create an IsolatedVenvPlugin instance
                isolated_plugin = IsolatedVenvPlugin(
                    config=plugin_config,
                    plugin_dirs=[str(self.plugin_folder)],
                )

                venv_python = self._get_venv_python_executable(isolated_plugin.plugin_path / ".venv")
                subprocess.run(
                    [venv_python, "-m", "pip", "uninstall", "-y", package_name],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                isolated_plugin.remove_venv()
                logger.info("Successfully uninstalled package: %s", package_name)
                return True
            else:
                subprocess.run(
                    [self.python_executable, "-m", "pip", "uninstall", "-y", package_name],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            logger.info("Successfully uninstalled package: %s", package_name)
            return True

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to uninstall {package_name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error uninstalling {package_name}: {str(e)}") from e

    def install_from_local(self, source: Path) -> tuple[PluginManifest, Path]:
        """Install a plugin from a local source directory.

        This method performs the following steps:
        1. Locates and loads pyproject.toml from source or subdirectories
        2. Finds and loads the plugin-manifest.yaml from source or subdirectories
        3. Parses and validates the manifest
        4. For isolated_venv plugins: initializes the target venv and installs in editable mode
        5. For other plugins: installs in editable mode into current environment
        6. Persists the manifest to the plugin catalog
        7. Finds and saves versions.json if available
        8. Updates the plugin version registry

        Args:
            source: Path to the local plugin source directory.

        Returns:
            Tuple of (PluginManifest, installation_path) where installation_path is the
            path where the plugin was installed.

        Raises:
            FileNotFoundError: If pyproject.toml or plugin-manifest.yaml is not found in source or subdirectories.
            RuntimeError: If installation fails.
        """
        # Step 1: Find and load pyproject.toml in source or subdirectories
        pyproject_path = None
        pyproject_data = None

        # Check in the source directory itself
        candidate = source / "pyproject.toml"
        if candidate.exists():
            pyproject_path = candidate
        else:
            # Search in subdirectories (one level deep)
            for subdir in source.iterdir():
                if subdir.is_dir():
                    candidate = subdir / "pyproject.toml"
                    if candidate.exists():
                        pyproject_path = candidate
                        break

        if pyproject_path is None:
            raise FileNotFoundError(f"pyproject.toml not found in {source} or its immediate subdirectories")

        logger.info("Found pyproject.toml at: %s", pyproject_path)

        # Load and parse the pyproject.toml
        try:
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
            logger.info(
                "Successfully loaded pyproject.toml with project name: %s",
                pyproject_data.get("project", {}).get("name", "unknown"),
            )
        except Exception as e:
            raise RuntimeError(f"Failed to parse pyproject.toml at {pyproject_path}: {str(e)}") from e

        # Step 2: Find plugin-manifest.yaml in source or subdirectories
        manifest_path = None

        # Check in the source directory itself
        candidate = source / "plugin-manifest.yaml"
        if candidate.exists():
            manifest_path = candidate
        else:
            # Search in subdirectories (one level deep)
            for subdir in source.iterdir():
                if subdir.is_dir():
                    candidate = subdir / "plugin-manifest.yaml"
                    if candidate.exists():
                        manifest_path = candidate
                        break

        if manifest_path is None:
            raise FileNotFoundError(f"plugin-manifest.yaml not found in {source} or its immediate subdirectories")

        logger.info("Found plugin-manifest.yaml at: %s", manifest_path)

        # Step 2: Load and parse the manifest
        manifest_data = self._load_manifest_file(manifest_path)
        manifest = self._normalize_manifest_data(manifest_data, pyproject_data["project"]["name"], None)
        manifest.local = str(source.resolve())

        logger.info("Loaded manifest for plugin: %s (kind: %s)", manifest.name, manifest.kind)

        plugin_path = None

        # Step 3: Install based on plugin kind
        if manifest.kind == "isolated_venv":
            logger.info("Installing isolated_venv plugin from local source: %s", source)

            try:
                # Import here to avoid circular dependency
                from cpex.framework.isolated.client import IsolatedVenvPlugin
                from cpex.framework.models import PluginMode

                # Create a temporary PluginConfig from the manifest
                plugin_config = manifest.create_instance_config(
                    instance_name=manifest.name,
                    mode=PluginMode.SEQUENTIAL,
                    priority=100,
                )

                # Create an IsolatedVenvPlugin instance
                isolated_plugin = IsolatedVenvPlugin(
                    config=plugin_config,
                    plugin_dirs=[str(self.plugin_folder)],
                )

                # Initialize the venv (creates venv directory structure)
                import asyncio
                import concurrent.futures

                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                if loop is None:
                    asyncio.run(isolated_plugin.initialize())
                else:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                        ex.submit(asyncio.run, isolated_plugin.initialize()).result()

                # Get the venv python executable
                venv_path = isolated_plugin.plugin_path / ".venv"
                venv_python = self._get_venv_python_executable(venv_path)

                # Install the plugin in editable mode into the isolated venv
                logger.info("Installing plugin in editable mode into isolated venv: %s", venv_path)
                subprocess.run(
                    [venv_python, "-m", "pip", "install", "-e", str(source)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )

                plugin_path = isolated_plugin.plugin_path
                logger.info("Successfully installed %s into isolated venv at %s", manifest.name, plugin_path)

            except Exception as e:
                raise RuntimeError(f"Failed to install isolated_venv plugin from {source}: {str(e)}") from e

        else:
            # Install into current environment for non-isolated plugins
            logger.info("Installing plugin from local source into current environment: %s", source)

            try:
                subprocess.run(
                    [self.python_executable, "-m", "pip", "install", "-e", str(source)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )

                # For non-isolated plugins, the plugin_path is the same folder that hosts the plugin-manifest.yaml
                plugin_path = Path(str(manifest_path).removesuffix(manifest_path.name))
                if plugin_path is None:
                    # Fallback to source path if package path not found
                    plugin_path = source

                logger.info("Successfully installed %s into current environment at %s", manifest.name, plugin_path)

            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to install plugin from {source}: {e.stderr}") from e
            except Exception as e:
                raise RuntimeError(f"Unexpected error installing plugin from {source}: {str(e)}") from e

        # Step 4: Persist to catalog
        self._persist_manifest(manifest, manifest.name)

        # Step 5: Find and save versions.json if available
        actual_plugin_path = self._find_and_load_versions_json(manifest, plugin_path, manifest.name)

        # Step 6: Update the plugin version registry
        self.update_plugin_version_registry(manifest=manifest, relpath=plugin_path)

        logger.info("Successfully installed and cataloged %s from local source", manifest.name)

        # Return the actual plugin path if found, otherwise the original plugin_path
        final_path = actual_plugin_path if actual_plugin_path is not None else plugin_path
        return manifest, final_path
