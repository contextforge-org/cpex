# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/tools/test_catalog.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Tests for the cpex.tools.catalog module.
"""

# Standard
import base64
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

# Third-Party
import httpx
import pytest
import yaml

# First-Party
from cpex.tools.catalog import PluginCatalog
from cpex.framework.models import PluginManifest, Monorepo


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
        "monorepo": Monorepo(package_source="https://github.com/org/repo#subdirectory=plugin", repo_url="https://github.com/org/repo", package_folder="plugin"),
    }
    defaults.update(kwargs)
    return PluginManifest(**defaults)


@pytest.fixture
def mock_github_env():
    """Fixture to provide a mocked GitHub environment."""
    with (
        patch.dict("os.environ", {"PLUGINS_GITHUB_TOKEN": "test_token"}),
        patch("cpex.tools.catalog.Github"),
    ):
        yield


class TestPluginCatalogInit:
    """Tests for PluginCatalog initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default environment variables."""
        with (
            patch.dict("os.environ", {"PLUGINS_GITHUB_TOKEN": "test_token"}, clear=True),
            patch("cpex.tools.catalog.Github"),
        ):
            catalog = PluginCatalog()
            assert catalog.github_api == "api.github.com"
            assert catalog.github_token == "test_token"
            assert catalog.monorepos == ["https://github.com/ibm/cpex-plugins"]
            assert catalog.plugin_folder == "plugins"
            assert catalog.manifests == []
            assert catalog.python_executable == sys.executable

    def test_init_with_custom_env_vars(self):
        """Test initialization with custom environment variables."""
        with (
            patch.dict(
                "os.environ",
                {
                    "PLUGINS_GITHUB_API": "api.github.example.com",
                    "PLUGINS_GITHUB_TOKEN": "test_token",
                    "PLUGINS_REPO_URLS": "https://github.com/org/repo1,https://github.com/org/repo2",
                    "PLUGINS_FOLDER": "custom_plugins",
                },
            ),
            patch("cpex.tools.catalog.Github"),
        ):
            catalog = PluginCatalog()
            assert catalog.github_api == "api.github.example.com"
            assert catalog.github_token == "test_token"
            assert catalog.monorepos == ["https://github.com/org/repo1", "https://github.com/org/repo2"]
            assert catalog.plugin_folder == "custom_plugins"

    def test_get_python_executable(self):
        """Test _get_python_executable returns sys.executable."""
        with (
            patch.dict("os.environ", {"PLUGINS_GITHUB_TOKEN": "test_token"}),
            patch("cpex.tools.catalog.Github"),
        ):
            catalog = PluginCatalog()
            assert catalog._get_python_executable() == sys.executable


class TestPluginCatalogFolderOperations:
    """Tests for folder creation operations."""

    def test_create_output_folder(self, tmp_path, mock_github_env):
        """Test creating the output folder."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "test-catalog")
        catalog.create_output_folder()
        assert (tmp_path / "test-catalog").exists()

    def test_create_folder(self, tmp_path, mock_github_env):
        """Test creating a folder with relative path."""
        catalog = PluginCatalog()
        catalog.create_folder(tmp_path, "subdir/file.txt")
        assert (tmp_path / "subdir").exists()

    def test_create_plugin_folder(self, tmp_path, mock_github_env):
        """Test creating a plugin folder."""
        catalog = PluginCatalog()
        catalog.plugin_folder = str(tmp_path / "plugins")
        catalog.create_plugin_folder("test_plugin/plugin.py")
        assert (tmp_path / "plugins" / "test_plugin").exists()

    def test_create_catalog_folder(self, tmp_path, mock_github_env):
        """Test creating a catalog folder."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.create_catalog_folder("test_plugin/plugin-manifest.yaml")
        assert (tmp_path / "catalog" / "test_plugin").exists()


class TestPluginCatalogSaveOperations:
    """Tests for save operations."""

    def test_save_content(self, tmp_path, mock_github_env):
        """Test saving content to a file."""
        catalog = PluginCatalog()
        test_content = "test content"
        catalog.save_content(tmp_path, test_content, "test.txt")
        assert (tmp_path / "test.txt").read_text() == test_content

    def test_save_plugin_content(self, tmp_path, mock_github_env):
        """Test saving plugin content."""
        catalog = PluginCatalog()
        catalog.plugin_folder = str(tmp_path / "plugins")
        (tmp_path / "plugins").mkdir()
        test_content = "plugin code"
        catalog.save_plugin_content(test_content, "plugin.py")
        assert (tmp_path / "plugins" / "plugin.py").read_text() == test_content

    def test_save_catalog_content(self, tmp_path, mock_github_env):
        """Test saving catalog content."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        (tmp_path / "catalog").mkdir()
        test_content = "catalog data"
        catalog.save_catalog_content(test_content, "manifest.yaml")
        assert (tmp_path / "catalog" / "manifest.yaml").read_text() == test_content

    def test_save_manifest_content(self, tmp_path, mock_github_env):
        """Test saving manifest content with transformations."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog_dir = tmp_path / "catalog" / "test_plugin"
        catalog_dir.mkdir(parents=True)
        
        manifest_yaml = """
name: test_plugin
version: 1.0.0
kind: native
description: Test
author: Test Author
available_hooks: [tools]
default_configs:
  key: value
"""
        repo_url = httpx.URL("https://github.com/org/repo")
        catalog.save_manifest_content(manifest_yaml, "test_plugin/plugin-manifest.yaml", repo_url)
        
        saved_file = tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml"
        assert saved_file.exists()
        
        saved_data = yaml.safe_load(saved_file.read_text())
        assert saved_data["monorepo"]["package_source"] == "https://github.com/org/repo#subdirectory=test_plugin"
        assert "tags" in saved_data
        assert "default_config" in saved_data
        assert "default_configs" not in saved_data  # Should be renamed to default_config

    def test_save_manifest_content_without_name(self, tmp_path, mock_github_env):
        """Test saving manifest content without name field."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog_dir = tmp_path / "catalog" / "test_plugin"
        catalog_dir.mkdir(parents=True)
        
        manifest_yaml = """
version: 1.0.0
kind: native
description: Test
author: Test Author
available_hooks: [tools]
default_config:
  key: value
"""
        repo_url = httpx.URL("https://github.com/org/repo")
        catalog.save_manifest_content(manifest_yaml, "test_plugin/plugin-manifest.yaml", repo_url)
        
        saved_file = tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml"
        assert saved_file.exists()
        
        saved_data = yaml.safe_load(saved_file.read_text())
        assert saved_data["name"] == "test_plugin"  # Should be set from path

    def test_save_manifest_content_with_null_default_configs(self, tmp_path, mock_github_env):
        """Test saving manifest content with null default_configs."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog_dir = tmp_path / "catalog" / "test_plugin"
        catalog_dir.mkdir(parents=True)
        
        manifest_yaml = """
name: test_plugin
version: 1.0.0
kind: native
description: Test
author: Test Author
available_hooks: [tools]
default_configs: null
"""
        repo_url = httpx.URL("https://github.com/org/repo")
        catalog.save_manifest_content(manifest_yaml, "test_plugin/plugin-manifest.yaml", repo_url)
        
        saved_file = tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml"
        assert saved_file.exists()
        
        saved_data = yaml.safe_load(saved_file.read_text())
        assert saved_data["default_config"] == {}  # Should be empty dict


class TestPluginCatalogDownloadOperations:
    """Tests for download operations."""

    def test_download_contents_success(self, tmp_path, mock_github_env):
        """Test successful download of contents."""
        with patch("cpex.tools.catalog.httpx.get") as mock_get:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            # Mock the HTTP response
            manifest_content = "name: test\nversion: 1.0.0\nkind: native\ndescription: Test\nauthor: Test\navailable_hooks: [tools]"
            b64_content = base64.b64encode(manifest_content.encode()).decode()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"content": b64_content}
            mock_get.return_value = mock_response
            
            repo_url = httpx.URL("https://github.com/org/repo")
            # download_contents calls create_catalog_folder which creates the directory
            # then save_manifest_content writes the file
            catalog.download_contents("https://api.github.com/file", {}, "test_plugin/plugin-manifest.yaml", repo_url)
            
            assert (tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml").exists()

    def test_download_contents_failure(self, tmp_path, mock_github_env):
        """Test failed download of contents."""
        with (
            patch("cpex.tools.catalog.httpx.get") as mock_get,
            patch("cpex.tools.catalog.logger") as mock_logger,
        ):
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            mock_response = Mock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response
            
            repo_url = httpx.URL("https://github.com/org/repo")
            catalog.download_contents("https://api.github.com/file", {}, "test/plugin-manifest.yaml", repo_url)
            
            mock_logger.error.assert_called_once()


class TestPluginCatalogLoadOperations:
    """Tests for load operations."""

    def test_load_no_output_folder(self, tmp_path, mock_github_env):
        """Test load when output folder doesn't exist."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "nonexistent")
            catalog.load()
            assert catalog.manifests == []
            mock_logger.warning.assert_called()

    def test_load_no_manifest_files(self, tmp_path, mock_github_env):
        """Test load when no manifest files exist."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            (tmp_path / "catalog").mkdir()
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            catalog.load()
            assert catalog.manifests == []
            assert mock_logger.warning.call_count >= 1

    def test_load_with_manifest_files(self, tmp_path, mock_github_env):
        """Test load with valid manifest files."""
        catalog_dir = tmp_path / "catalog" / "test_plugin"
        catalog_dir.mkdir(parents=True)
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = catalog_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.load()
        
        assert len(catalog.manifests) == 1
        assert catalog.manifests[0].name == "test_plugin"

    def test_load_with_invalid_manifest(self, tmp_path, mock_github_env):
        """Test load with invalid manifest file."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog_dir = tmp_path / "catalog"
            catalog_dir.mkdir()
            
            manifest_file = catalog_dir / "plugin-manifest.yaml"
            manifest_file.write_text("invalid: yaml: content:")
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            catalog.load()
            
            assert len(catalog.manifests) == 0
            mock_logger.error.assert_called()


class TestPluginCatalogSearchOperations:
    """Tests for search operations."""

    def test_search_empty_catalog(self, mock_github_env):
        """Test search with empty catalog."""
        catalog = PluginCatalog()
        catalog.manifests = []
        result = catalog.search("test")
        assert result is None

    def test_search_by_name(self, mock_github_env):
        """Test search by plugin name."""
        catalog = PluginCatalog()
        catalog.manifests = [
            create_test_manifest(name="test_plugin", tags=["plugin"]),
            create_test_manifest(name="another_plugin", tags=["other"]),
        ]
        result = catalog.search("test")
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "test_plugin"

    def test_search_by_tag(self, mock_github_env):
        """Test search by tag."""
        catalog = PluginCatalog()
        catalog.manifests = [
            create_test_manifest(name="plugin1", tags=["security"]),
            create_test_manifest(name="plugin2", tags=["data"]),
        ]
        result = catalog.search("security")
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "plugin1"

    def test_search_no_match(self, mock_github_env):
        """Test search with no matches."""
        catalog = PluginCatalog()
        catalog.manifests = [create_test_manifest(name="test_plugin")]
        result = catalog.search("nonexistent")
        assert result is None

    def test_search_loads_manifests_if_empty(self, tmp_path, mock_github_env):
        """Test search loads manifests if catalog is empty."""
        catalog_dir = tmp_path / "catalog" / "test_plugin"
        catalog_dir.mkdir(parents=True)
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = catalog_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        result = catalog.search("test")
        
        assert result is not None
        assert len(result) == 1


class TestPluginCatalogInstallFromPypi:
    """Tests for install_from_pypi method."""

    def test_install_from_pypi_success(self, tmp_path, mock_github_env):
        """Test successful installation from PyPI."""
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            # Create manifest file
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            manifest_data = {
                "name": "test_package",
                "version": "1.0.0",
                "kind": "native",
                "description": "Test",
                "author": "Test Author",
                "tags": ["test"],
                "available_hooks": ["tools"],
                "default_config": {},
            }
            manifest_file = package_dir / "plugin-manifest.yaml"
            manifest_file.write_text(yaml.safe_dump(manifest_data))
            
            # Setup mock distribution with plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_manifest_file = Mock()
            mock_manifest_file.name = "plugin-manifest.yaml"
            mock_dist.files = [mock_manifest_file]
            mock_dist.locate_file.return_value = manifest_file
            mock_distributions.return_value = [mock_dist]
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            result = catalog.install_from_pypi("test_package")
            
            mock_subprocess.assert_called_once()
            assert result.name == "test_package"

    def test_install_from_pypi_install_failure(self, mock_github_env):
        """Test installation failure from PyPI."""
        with patch("cpex.tools.catalog.subprocess.run", side_effect=Exception("Install failed")):
            catalog = PluginCatalog()
            with pytest.raises(RuntimeError, match="Unexpected error installing"):
                catalog.install_from_pypi("test_package")

    def test_install_from_pypi_package_not_found(self, mock_github_env):
        """Test when package is not found after installation."""
        with (
            patch("cpex.tools.catalog.subprocess.run"),
            patch("cpex.tools.catalog.importlib.metadata.distributions", return_value=[]),
            patch("cpex.tools.catalog.importlib.util.find_spec", return_value=None),
        ):
            catalog = PluginCatalog()
            with pytest.raises(RuntimeError, match="Could not find installed package"):
                catalog.install_from_pypi("test_package")

    def test_install_from_pypi_manifest_not_found(self, tmp_path, mock_github_env):
        """Test when manifest file is not found in package."""
        with (
            patch("cpex.tools.catalog.subprocess.run"),
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            # Setup mock distribution without plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_file = Mock()
            mock_file.name = "__init__.py"
            mock_dist.files = [mock_file]
            mock_dist.locate_file.return_value = tmp_path / "test_package" / "__init__.py"
            mock_distributions.return_value = [mock_dist]
            
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            with pytest.raises(RuntimeError, match="Could not find installed package"):
                catalog.install_from_pypi("test_package")

    def test_install_from_pypi_invalid_manifest(self, tmp_path, mock_github_env):
        """Test when manifest file is invalid."""
        with (
            patch("cpex.tools.catalog.subprocess.run"),
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            manifest_file = package_dir / "plugin-manifest.yaml"
            manifest_file.write_text("invalid: yaml: content:")
            
            # Setup mock distribution with plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_manifest_file = Mock()
            mock_manifest_file.name = "plugin-manifest.yaml"
            mock_dist.files = [mock_manifest_file]
            mock_dist.locate_file.return_value = manifest_file
            mock_distributions.return_value = [mock_dist]
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            with pytest.raises(RuntimeError, match="Failed to parse manifest YAML"):
                catalog.install_from_pypi("test_package")


class TestPluginCatalogInstallFolderViaPip:
    """Tests for install_folder_via_pip method."""

    def test_install_folder_via_pip_success(self, tmp_path, mock_github_env):
        """Test successful installation from monorepo."""
        with patch("cpex.tools.catalog.subprocess.run") as mock_subprocess:
            manifest = create_test_manifest(
                monorepo=Monorepo(
                    package_source="https://github.com/org/repo#subdirectory=plugin",
                    repo_url="https://github.com/org/repo",
                    package_folder="plugin"
                )
            )
            
            catalog = PluginCatalog()
            catalog.install_folder_via_pip(manifest)
            mock_subprocess.assert_called_once()

    def test_install_folder_via_pip_no_monorepo(self, mock_github_env):
        """Test installation fails when monorepo is None."""
        manifest = create_test_manifest(monorepo=None)
        
        catalog = PluginCatalog()
        with pytest.raises(RuntimeError, match="PluginManifest.monorepo can not be None"):
            catalog.install_folder_via_pip(manifest)

    def test_install_folder_via_pip_subprocess_error(self, mock_github_env):
        """Test installation fails on subprocess error."""
        # Create a CalledProcessError with proper arguments
        error = subprocess.CalledProcessError(1, ["pip"], stderr="Install failed")
        with patch("cpex.tools.catalog.subprocess.run", side_effect=error):
            manifest = create_test_manifest(
                monorepo=Monorepo(
                    package_source="https://github.com/org/repo#subdirectory=plugin",
                    repo_url="https://github.com/org/repo",
                    package_folder="plugin"
                )
            )
            
            catalog = PluginCatalog()
            with pytest.raises(RuntimeError, match="Failed to install"):
                catalog.install_folder_via_pip(manifest)


class TestPluginCatalogSaveManifest:
    """Tests for save_manifest method."""

    def test_save_manifest(self, tmp_path, mock_github_env):
        """Test saving a manifest to the catalog."""
        catalog_dir = tmp_path / "catalog" / "test_plugin"
        catalog_dir.mkdir(parents=True)
        
        manifest = create_test_manifest(name="test_plugin")
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.save_manifest(manifest, "test_plugin/plugin-manifest.yaml")
        
        saved_file = tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml"
        assert saved_file.exists()
        
        saved_data = yaml.safe_load(saved_file.read_text())
        assert saved_data["name"] == "test_plugin"


class TestPluginCatalogDownloadFile:
    """Tests for download_file method."""

    def test_download_file_success(self, mock_github_env):
        """Test successful file download."""
        with patch("cpex.tools.catalog.httpx.get") as mock_get:
            catalog = PluginCatalog()
            
            # Mock the HTTP response
            manifest_content = "name: test\nversion: 1.0.0"
            b64_content = base64.b64encode(manifest_content.encode()).decode()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"content": b64_content}
            mock_get.return_value = mock_response
            
            result = catalog.download_file("https://api.github.com/file", {})
            
            assert result == manifest_content

    def test_download_file_failure(self, mock_github_env):
        """Test failed file download."""
        with (
            patch("cpex.tools.catalog.httpx.get") as mock_get,
            patch("cpex.tools.catalog.logger") as mock_logger,
        ):
            catalog = PluginCatalog()
            
            mock_response = Mock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response
            
            result = catalog.download_file("https://api.github.com/file", {})
            
            assert result is None
            mock_logger.error.assert_called_once()


class TestPluginCatalogFindAndSavePluginManifest:
    """Tests for find_and_save_plugin_manifest method."""

    def test_find_and_save_plugin_manifest_success(self, tmp_path, mock_github_env):
        """Test successful finding and saving of plugin manifest."""
        with patch("cpex.tools.catalog.httpx.get") as mock_get:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            # Mock search response
            search_response = Mock()
            search_response.status_code = 200
            search_response.json.return_value = {
                "items": [
                    {
                        "name": "plugin-manifest.yaml",
                        "path": "test_plugin/plugin-manifest.yaml",
                        "git_url": "https://api.github.com/repos/org/repo/git/blobs/abc123"
                    }
                ]
            }
            
            # Mock file content response
            manifest_content = "name: test\nversion: 1.0.0\nkind: native\ndescription: Test\nauthor: Test\navailable_hooks: [tools]"
            b64_content = base64.b64encode(manifest_content.encode()).decode()
            file_response = Mock()
            file_response.status_code = 200
            file_response.json.return_value = {"content": b64_content}
            
            mock_get.side_effect = [search_response, file_response]
            
            repo_url = httpx.URL("https://github.com/org/repo")
            catalog.find_and_save_plugin_manifest("test_plugin", "test_plugin", repo_url, {})
            
            saved_file = tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml"
            assert saved_file.exists()


class TestPluginCatalogUpdateCatalogWithCargo:
    """Tests for update_catalog_with_cargo method."""

    def test_update_catalog_with_cargo_success(self, tmp_path, mock_github_env):
        """Test successful catalog update with Cargo workspace."""
        with patch("cpex.tools.catalog.httpx.get") as mock_get:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            catalog.monorepos = ["https://github.com/org/repo"]
            
            # Mock Cargo.toml response
            cargo_content = '[workspace]\nmembers = ["plugin1"]'
            b64_cargo = base64.b64encode(cargo_content.encode()).decode()
            cargo_response = Mock()
            cargo_response.status_code = 200
            cargo_response.json.return_value = {"content": b64_cargo}
            
            # Mock pyproject.toml response
            pyproject_content = '[project]\nname = "test_plugin"'
            b64_pyproject = base64.b64encode(pyproject_content.encode()).decode()
            pyproject_response = Mock()
            pyproject_response.status_code = 200
            pyproject_response.json.return_value = {"content": b64_pyproject}
            
            # Mock search response for manifest
            search_response = Mock()
            search_response.status_code = 200
            search_response.json.return_value = {
                "items": [
                    {
                        "name": "plugin-manifest.yaml",
                        "path": "plugin1/plugin-manifest.yaml",
                        "git_url": "https://api.github.com/repos/org/repo/git/blobs/abc123"
                    }
                ]
            }
            
            # Mock manifest content response
            manifest_content = "name: test\nversion: 1.0.0\nkind: native\ndescription: Test\nauthor: Test\navailable_hooks: [tools]"
            b64_manifest = base64.b64encode(manifest_content.encode()).decode()
            manifest_response = Mock()
            manifest_response.status_code = 200
            manifest_response.json.return_value = {"content": b64_manifest}
            
            mock_get.side_effect = [cargo_response, pyproject_response, search_response, manifest_response]
            
            catalog.update_catalog_with_cargo()
            
            assert (tmp_path / "catalog").exists()


class TestPluginCatalogSearchEdgeCases:
    """Tests for search method edge cases."""

    def test_search_with_none_plugin_name(self, mock_github_env):
        """Test search with None as plugin name returns all manifests."""
        catalog = PluginCatalog()
        catalog.manifests = [
            create_test_manifest(name="plugin1"),
            create_test_manifest(name="plugin2"),
        ]
        result = catalog.search(None)
        assert result is not None
        assert len(result) == 2


class TestPluginCatalogInstallFromPypiExtended:
    """Extended tests for install_from_pypi method."""

    def test_install_from_pypi_with_version_constraint(self, tmp_path, mock_github_env):
        """Test installation with version constraint."""
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            manifest_data = {
                "name": "test_package",
                "version": "1.0.0",
                "kind": "native",
                "description": "Test",
                "author": "Test Author",
                "tags": ["test"],
                "available_hooks": ["tools"],
                "default_config": {},
            }
            manifest_file = package_dir / "plugin-manifest.yaml"
            manifest_file.write_text(yaml.safe_dump(manifest_data))
            
            # Setup mock distribution with plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_manifest_file = Mock()
            mock_manifest_file.name = "plugin-manifest.yaml"
            mock_dist.files = [mock_manifest_file]
            mock_dist.locate_file.return_value = manifest_file
            mock_distributions.return_value = [mock_dist]
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            result = catalog.install_from_pypi("test_package", ">=1.0.0")
            
            mock_subprocess.assert_called_once()
            assert result.name == "test_package"
            assert result.package_info is not None
            assert result.package_info.version_constraint == ">=1.0.0"

    def test_install_from_pypi_with_default_configs(self, tmp_path, mock_github_env):
        """Test installation with default_configs field."""
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            manifest_data = {
                "name": "test_package",
                "version": "1.0.0",
                "kind": "native",
                "description": "Test",
                "author": "Test Author",
                "tags": ["test"],
                "available_hooks": ["tools"],
                "default_configs": {"key": "value"},
            }
            manifest_file = package_dir / "plugin-manifest.yaml"
            manifest_file.write_text(yaml.safe_dump(manifest_data))
            
            # Setup mock distribution with plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_manifest_file = Mock()
            mock_manifest_file.name = "plugin-manifest.yaml"
            mock_dist.files = [mock_manifest_file]
            mock_dist.locate_file.return_value = manifest_file
            mock_distributions.return_value = [mock_dist]
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            result = catalog.install_from_pypi("test_package")
            
            assert result.default_config == {"key": "value"}

    def test_install_from_pypi_with_existing_package_info(self, tmp_path, mock_github_env):
        """Test installation with existing package_info."""
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            manifest_data = {
                "name": "test_package",
                "version": "1.0.0",
                "kind": "native",
                "description": "Test",
                "author": "Test Author",
                "tags": ["test"],
                "available_hooks": ["tools"],
                "default_config": {},
                "package_info": {
                    "pypi_package": "old_name",
                    "version_constraint": ">=0.1.0"
                }
            }
            manifest_file = package_dir / "plugin-manifest.yaml"
            manifest_file.write_text(yaml.safe_dump(manifest_data))
            
            # Setup mock distribution with plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_manifest_file = Mock()
            mock_manifest_file.name = "plugin-manifest.yaml"
            mock_dist.files = [mock_manifest_file]
            mock_dist.locate_file.return_value = manifest_file
            mock_distributions.return_value = [mock_dist]
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            result = catalog.install_from_pypi("test_package", ">=2.0.0")
            
            assert result.package_info is not None
            assert result.package_info.pypi_package == "test_package"
            assert result.package_info.version_constraint == ">=2.0.0"

    def test_install_from_pypi_with_null_default_configs_in_manifest(self, tmp_path, mock_github_env):
        """Test installation with null default_configs in manifest."""
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.importlib.metadata.distributions") as mock_distributions,
        ):
            package_dir = tmp_path / "test_package"
            package_dir.mkdir()
            manifest_data = {
                "name": "test_package",
                "version": "1.0.0",
                "kind": "native",
                "description": "Test",
                "author": "Test Author",
                "tags": ["test"],
                "available_hooks": ["tools"],
                "default_configs": None,
            }
            manifest_file = package_dir / "plugin-manifest.yaml"
            manifest_file.write_text(yaml.safe_dump(manifest_data))
            
            # Setup mock distribution with plugin-manifest.yaml file
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_manifest_file = Mock()
            mock_manifest_file.name = "plugin-manifest.yaml"
            mock_dist.files = [mock_manifest_file]
            mock_dist.locate_file.return_value = manifest_file
            mock_distributions.return_value = [mock_dist]
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            result = catalog.install_from_pypi("test_package")
            
            # default_config should be empty dict when default_configs is None
            assert result.default_config == {}


# Made with Bob
