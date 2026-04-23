# -*- coding: utf-8 -*-
"""Location: ./cpex/tools/catalog.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

This module implements the plugin catalog object.
"""

import base64
import logging
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Optional
import uuid

import httpx
import shutil
import tarfile
import tempfile
import zipfile

import yaml
from github import Auth, Github

from cpex.framework.models import PiPyRepo, PluginManifest, PluginPackageInfo
from cpex.framework.utils import find_package_path
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
        relpath = Path(self.catalog_folder) / path
        updated_content = yaml.safe_dump(manifest.model_dump(), default_flow_style=False)
        relpath.write_text(updated_content, encoding="utf-8")

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
            logger.error("Failed to download file: %s status_code: %d", item["path"], str(e))

    def _search_github_code(self, repo_path: str, member: str, headers) -> list[dict] | None:
        """Search GitHub for plugin-manifest.yaml files in a specific path using PyGithub API.

        Args:
            repo_path: Repository path (e.g., 'owner/repo')
            member: Directory path within the repository
            headers: HTTP headers for authentication (kept for compatibility but not used)

        Returns:
            List of search result items as dicts with 'name' and 'git_url' keys, or None if request failed
        """
        try:
            # Build search query for PyGithub
            if member is not None:
                query = f"repo:{repo_path} path:{member} filename:plugin-manifest extension:yaml"
            else:
                query = f"repo:{repo_path} filename:plugin-manifest extension:yaml"
            # Use PyGithub's search_code method
            search_results = self.gh.search_code(query=query)

            logger.info("Found %d plugin-manifest files in %s/%s", search_results.totalCount, repo_path, member)

            # Convert PyGithub ContentFile objects to dict format compatible with existing code
            items = []
            for content_file in search_results:
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

    def _transform_manifest_data(self, manifest_content: dict, name: str, member: str, repo_url: httpx.URL) -> dict:
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
        return True

    def find_and_save_plugin_manifest(
        self, member: str, name: str, repo_url: httpx.URL, headers, gh_repo
    ) -> PluginManifest | None:
        """Find the plugin-manifest.yaml relative to the supplied member folder,
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
        relpath = Path(self.catalog_folder) / name / "plugin-manifest.yaml"

        items = self._search_github_code(repo_path, member, headers)
        if items is None:
            return None

        for item in items:
            if self._process_manifest_item(item, name, member, repo_url, headers, relpath, repo_path, gh_repo):
                break  # Successfully processed first valid manifest

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

    def install_folder_via_pip(self, manifest: PluginManifest) -> Path | None:
        """
        Runs a pip install using subfolder syntax for monorepo plugins.
        For isolated_venv plugins, checks manifest kind BEFORE installing to avoid dependency conflicts.
        e.g. "git+https://github.com[extra]&subdirectory=folder_name"

        Args:
            manifest: The PluginManifest of the plugin to be installed

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
                package_path = self._download_monorepo_folder_to_temp(repo_url, manifest.name)
                plugin_path = self._initialize_isolated_venv(manifest, package_path)
                logger.info("Isolated venv initialized. Plugin will be auto-installed via requirements.txt")
            else:
                # For non-isolated plugins, install normally into CLI's venv
                logger.info("Installing non-isolated plugin from monorepo: %s", manifest.name)
                subprocess.run(
                    [self.python_executable, "-m", "pip", "install", repo_url], check=True, capture_output=True, text=True
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
                )
            else:
                # Use subprocess.run for better error handling
                subprocess.run(
                    [self.python_executable, "-m", "pip", "install", tgt], check=True, capture_output=True, text=True
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

    def _download_monorepo_folder_to_temp(self, repo_url: str, package_name: str) -> Path:
        """Download monorepo folder to temporary directory.
        Args:
            repo_url: The URL of the monorepo.
        Returns:
            Path to the downloaded monorepo folder.
        """
        try:
            tmpid    = uuid.uuid4()
            temp_dir = Path(tempfile.mkdtemp(prefix=f"cpex_plugin_{tmpid}_"))
            logger.info("Downloading monorepo folder to %s", temp_dir)

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
            download_args.append(repo_url)

            subprocess.run(download_args, check=True, capture_output=True, text=True)

            # Find the downloaded file
            downloaded_files = list(temp_dir.glob("*"))
            if not downloaded_files:
                raise RuntimeError(f"No files downloaded for {package_name}")
            package_file = downloaded_files[0]
            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir()

            # Extract the package
            if package_file.suffix == ".zip" or package_file.name.endswith(".zip"):
                with zipfile.ZipFile(package_file, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif package_file.suffix in [".gz", ".bz2"] or ".tar" in package_file.name:
                with tarfile.open(package_file, "r:*") as tar_ref:
                    tar_ref.extractall(extract_dir)
            else:
                raise RuntimeError(f"Unsupported package format: {package_file}")

            logger.info("Downloaded and extracted %s to %s", package_name, extract_dir)
            return extract_dir

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to download {package_name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error downloading {package_name}: {str(e)}") from e


    def _download_package_to_temp(
        self, package_name: str, version_constraint: str | None, use_test: bool = False
    ) -> Path:
        """Download package to a temporary directory without installing it.

        Args:
            package_name: The PyPI package name to download.
            version_constraint: Optional version constraint.
            use_test: Whether to use test.pypi.org.

        Returns:
            Path to the downloaded package directory.

        Raises:
            RuntimeError: If download fails.
        """

        try:
            # Create temporary directory
            temp_dir = Path(tempfile.mkdtemp(prefix=f"cpex_plugin_{package_name}_"))

            # Validate package name and constraint format
            ppi = PluginPackageInfo(pypi_package=package_name, version_constraint=version_constraint)
            tgt = ppi.pypi_package
            if ppi.version_constraint is not None:
                tgt = f"{tgt}{ppi.version_constraint}"

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

            subprocess.run(download_args, check=True, capture_output=True, text=True)

            # Find the downloaded file
            downloaded_files = list(temp_dir.glob("*"))
            if not downloaded_files:
                raise RuntimeError(f"No files downloaded for {package_name}")

            package_file = downloaded_files[0]
            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir()

            # Extract the package
            if package_file.suffix == ".whl" or package_file.name.endswith(".whl"):
                with zipfile.ZipFile(package_file, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif package_file.suffix in [".gz", ".bz2"] or ".tar" in package_file.name:
                with tarfile.open(package_file, "r:*") as tar_ref:
                    tar_ref.extractall(extract_dir)
            else:
                raise RuntimeError(f"Unsupported package format: {package_file}")

            logger.info("Downloaded and extracted %s to %s", package_name, extract_dir)
            return extract_dir

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to download {package_name}: {e.stderr}") from e
        except Exception as e:
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

    def _find_requirements_in_extracted_package(self, extract_dir: Path, package_name: str, requirements_file: str) -> Path:
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
        manifest_files = list(extract_dir.rglob(requirements_file))

        if not manifest_files:
            raise FileNotFoundError(f"requirements file {requirements_file} not found in {package_name} package")

        # Return the first manifest found
        return manifest_files[0]


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
            source_path = self._find_requirements_in_extracted_package(package_path, manifest.name, manifest.default_config["requirements_file"])
            shutil.copy(source_path, isolated_plugin.plugin_path / manifest.default_config["requirements_file"])
            # Initialize the venv (this will create venv and install requirements)
            import asyncio

            asyncio.run(isolated_plugin.initialize())

            logger.info("Successfully initialized isolated venv for %s", manifest.name)

            return isolated_plugin.plugin_path

        except Exception as e:
            raise RuntimeError(f"Failed to initialize isolated venv for {manifest.name}: {str(e)}") from e

    def install_from_pypi(
        self, plugin_package_name: str, version_constraint: str | None = None, use_pytest: bool = False
    ) -> PluginManifest:
        """Install Python package from PyPI and load its plugin-manifest.yaml.

        This method performs the following steps:
        1. Downloads package to check manifest (without installing for isolated_venv)
        2. Loads and parses the plugin-manifest.yaml
        3. Normalizes and validates the manifest data
        4. For isolated_venv plugins: initializes the target venv (plugin auto-installs via requirements.txt)
        5. For other plugins: installs normally into CLI's venv
        6. Persists the manifest to the plugin catalog

        Args:
            plugin_package_name: The name of the package hosted on PyPI.
            version_constraint: Optional version constraint (e.g., ">=1.0.0,<2.0.0").

        Returns:
            The loaded and validated plugin manifest.

        Raises:
            RuntimeError: If any step of the installation process fails.
            FileNotFoundError: If plugin-manifest.yaml is not found in the package.
        """

        # Step 1: Download package to temporary location to read manifest
        temp_extract_dir = self._download_package_to_temp(plugin_package_name, version_constraint, use_pytest)

        try:
            # Step 2: Find and load the manifest file
            manifest_path = self._find_manifest_in_extracted_package(temp_extract_dir, plugin_package_name)
            manifest_data = self._load_manifest_file(manifest_path)

            # Step 3: Normalize and validate the manifest
            manifest = self._normalize_manifest_data(manifest_data, plugin_package_name, version_constraint)

            package_path = manifest_path.parent

            plugin_path = None
            # Step 4: Handle based on plugin kind
            if manifest.kind == "isolated_venv":
                logger.info("Detected isolated_venv plugin: %s", manifest.name)
                plugin_path = self._initialize_isolated_venv(manifest, package_path)
                logger.info("Isolated venv initialized. Plugin auto-installed via requirements.txt")
            else:
                # For non-isolated plugins, install normally into CLI's venv
                logger.info("Installing non-isolated plugin: %s", manifest.name)
                self._install_package(plugin_package_name, version_constraint, use_pytest)

            # Step 5: Persist to catalog
            self._persist_manifest(manifest, plugin_package_name)

            logger.info("Successfully installed and cataloged %s", plugin_package_name)
            return manifest, plugin_path

        finally:
            # Clean up temporary directory
            if temp_extract_dir.exists():
                shutil.rmtree(temp_extract_dir.parent)

    def uninstall_package(self, package_name: str) -> bool:
        """Uninstall a Python package using pip.

        Args:
            package_name: The name of the package to uninstall.

        Returns:
            True if uninstallation was successful, False otherwise.

        Raises:
            RuntimeError: If the uninstallation process fails.
        """
        try:
            subprocess.run(
                [self.python_executable, "-m", "pip", "uninstall", "-y", package_name],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info("Successfully uninstalled package: %s", package_name)
            return True

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to uninstall {package_name}: {e.stderr}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error uninstalling {package_name}: {str(e)}") from e
