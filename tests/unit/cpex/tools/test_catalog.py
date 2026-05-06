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
import tarfile
import zipfile
from pathlib import Path
from unittest import mock
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
            patch.dict(
                "os.environ",
                {
                    "PLUGINS_GITHUB_TOKEN": "test_token",
                    "PLUGINS_GITHUB_API": "api.github.com",
                    "PLUGINS_REPO_URLS": "https://github.com/ibm/cpex-plugins",
                    "PLUGINS_FOLDER": "plugins",
                    "PLUGINS_CATALOG_FOLDER": "plugin-catalog",
                },
                clear=True,
            ),
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
            manifest_content = "name: test\nversion: 1.0.0\nkind: native\ndescription: Test\nauthor: Test\navailable_hooks: [tools]\ndefault_config: {}"
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

    def test_search_empty_catalog(self, tmp_path, mock_github_env):
        """Test search with empty catalog."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.manifests = []
        result = catalog.search("test")
        assert result is None

    def test_search_by_name(self, tmp_path, mock_github_env):
        """Test search by plugin name."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.manifests = [
            create_test_manifest(name="test_plugin", tags=["plugin"]),
            create_test_manifest(name="another_plugin", tags=["other"]),
        ]
        result = catalog.search("test")
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "test_plugin"

    def test_search_by_tag(self, tmp_path, mock_github_env):
        """Test search by tag."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.manifests = [
            create_test_manifest(name="plugin1", tags=["security"]),
            create_test_manifest(name="plugin2", tags=["data"]),
        ]
        result = catalog.search("security")
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "plugin1"

    def test_search_no_match(self, tmp_path, mock_github_env):
        """Test search with no matches."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
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
        # Create manifest file in temp directory
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
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
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.framework.utils.importlib.metadata.distributions") as mock_distributions,
            patch("cpex.framework.utils.importlib.util.find_spec") as mock_find_spec,
            patch("shutil.rmtree") as mock_rmtree,
        ):
            # Setup mock distribution
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_dist.files = None  # No files attribute for non-isolated plugins
            mock_distributions.return_value = [mock_dist]
            
            # Setup mock spec for find_spec fallback
            mock_spec = Mock()
            mock_spec.origin = str(package_dir / "__init__.py")
            mock_find_spec.return_value = mock_spec
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            manifest, plugin_path = catalog.install_from_pypi("test_package")
            
            # Should call subprocess.run for non-isolated plugin
            mock_subprocess.assert_called_once()
            assert manifest.name == "test_package"
            assert plugin_path == package_dir  # Non-isolated plugins return the package path
            # Should clean up temp directory
            mock_rmtree.assert_called_once()

    def test_install_from_pypi_install_failure(self, mock_github_env):
        """Test installation failure from PyPI."""
        with patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", side_effect=RuntimeError("Download failed")):
            catalog = PluginCatalog()
            with pytest.raises(RuntimeError, match="Download failed"):
                catalog.install_from_pypi("test_package")

    def test_install_from_pypi_package_not_found(self, tmp_path, mock_github_env):
        """Test when package is not found after installation (for isolated_venv plugins)."""
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
        package_dir.mkdir()
        manifest_data = {
            "name": "test_package",
            "version": "1.0.0",
            "kind": "isolated_venv",  # Changed to isolated_venv to trigger find_package_path
            "description": "Test",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = package_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("cpex.tools.catalog.subprocess.run"),
            patch("cpex.framework.utils.importlib.metadata.distributions", return_value=[]),
            patch("cpex.framework.utils.importlib.util.find_spec", return_value=None),
            patch("shutil.rmtree"),
        ):
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            with pytest.raises(RuntimeError, match="Failed to initialize isolated venv for test_package"):
                catalog.install_from_pypi("test_package")

    def test_install_from_pypi_manifest_not_found(self, tmp_path, mock_github_env):
        """Test when manifest file is not found in package."""
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", side_effect=FileNotFoundError("plugin-manifest.yaml not found")),
            patch("shutil.rmtree"),
        ):
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            with pytest.raises(FileNotFoundError, match="plugin-manifest.yaml not found"):
                catalog.install_from_pypi("test_package")

    def test_install_from_pypi_invalid_manifest(self, tmp_path, mock_github_env):
        """Test when manifest file is invalid."""
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
        package_dir.mkdir()
        manifest_file = package_dir / "plugin-manifest.yaml"
        manifest_file.write_text("invalid: yaml: content:")
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("shutil.rmtree"),
        ):
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
        catalog = PluginCatalog()
        
        # Mock the GitHub repository and file content
        mock_repo = Mock()
        mock_file_content = Mock()
        manifest_content = "name: test\nversion: 1.0.0"
        mock_file_content.decoded_content = manifest_content.encode()
        mock_repo.get_contents.return_value = mock_file_content
        catalog.gh.get_repo = Mock(return_value=mock_repo)
        
        item = {"path": "test_plugin/plugin-manifest.yaml"}
        result = catalog.download_file("org/repo", item, {}, mock_repo)
        
        assert result == manifest_content

    def test_download_file_failure(self, mock_github_env):
        """Test failed file download."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            # Mock the GitHub repository to raise an exception
            mock_repo = Mock(side_effect=Exception("Not found"))
            mock_repo.get_contents.return_value = Exception("Not found")
            item = {"path": "test_plugin/plugin-manifest.yaml"}
            result = catalog.download_file("org/repo", item, {}, mock_repo)
            
            assert result is None
            mock_logger.error.assert_called_once()


class TestPluginCatalogFindAndSavePluginManifest:
    """Tests for find_and_save_plugin_manifest method."""

    def test_find_and_save_plugin_manifest_success(self, tmp_path, mock_github_env):
        """Test successful finding and saving of plugin manifest."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Mock the search results
        mock_search_result = Mock()
        mock_content_file = Mock()
        mock_content_file.name = "plugin-manifest.yaml"
        mock_content_file.path = "test_plugin/plugin-manifest.yaml"
        mock_content_file.git_url = "https://api.github.com/repos/org/repo/git/blobs/abc123"
        mock_content_file.html_url = "https://github.com/org/repo/blob/main/test_plugin/plugin-manifest.yaml"
        
        mock_search_result.totalCount = 1
        mock_search_result.__iter__ = Mock(return_value=iter([mock_content_file]))
        
        catalog.gh.search_code = Mock(return_value=mock_search_result)
        
        # Mock the repository and file content
        mock_repo = Mock()
        manifest_content = "name: test\nversion: 1.0.0\nkind: native\ndescription: Test\nauthor: Test\navailable_hooks: [tools]\ndefault_config: {}"
        mock_file_content = Mock()
        mock_file_content.decoded_content = manifest_content.encode()
        mock_repo.get_contents.return_value = mock_file_content
        catalog.gh.get_repo = Mock(return_value=mock_repo)
        
        repo_url = httpx.URL("https://github.com/org/repo")
        catalog.find_and_save_plugin_manifest("test_plugin", "test_plugin", repo_url, {}, mock_repo)
        
        saved_file = tmp_path / "catalog" / "test_plugin" / "plugin-manifest.yaml"
        assert saved_file.exists()


class TestPluginCatalogUpdateCatalogWithPyproject:
    """Tests for update_catalog_with_pyproject method."""

    def test_update_catalog_with_pyproject_success(self, tmp_path, mock_github_env):
        """Test successful catalog update with pyproject.toml files."""
        with patch("cpex.tools.catalog.httpx.get") as mock_get:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            catalog.monorepos = ["https://github.com/org/repo"]
            
            # Mock search response for pyproject.toml files
            search_response = Mock()
            search_response.status_code = 200
            search_response.json.return_value = {
                "items": [
                    {
                        "name": "pyproject.toml",
                        "path": "plugin1/pyproject.toml"
                    }
                ]
            }
            
            # Mock pyproject.toml content response
            pyproject_content = '[project]\nname = "test_plugin"'
            b64_pyproject = base64.b64encode(pyproject_content.encode()).decode()
            pyproject_response = Mock()
            pyproject_response.status_code = 200
            pyproject_response.json.return_value = {"content": b64_pyproject}
            
            # Mock search response for manifest
            manifest_search_response = Mock()
            manifest_search_response.status_code = 200
            manifest_search_response.json.return_value = {
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
            
            mock_get.side_effect = [search_response, pyproject_response, manifest_search_response, manifest_response]
            
            catalog.update_catalog_with_pyproject()
            
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
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
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
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.framework.utils.importlib.metadata.distributions") as mock_distributions,
            patch("cpex.framework.utils.importlib.util.find_spec") as mock_find_spec,
            patch("shutil.rmtree"),
        ):
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_dist.files = None  # No files attribute for non-isolated plugins
            mock_distributions.return_value = [mock_dist]
            
            # Setup mock spec for find_spec fallback
            mock_spec = Mock()
            mock_spec.origin = str(package_dir / "__init__.py")
            mock_find_spec.return_value = mock_spec
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            manifest, plugin_path = catalog.install_from_pypi("test_package", ">=1.0.0")
            
            mock_subprocess.assert_called_once()
            assert manifest.name == "test_package"
            assert manifest.package_info is not None
            assert manifest.package_info.version_constraint == ">=1.0.0"

    def test_install_from_pypi_with_default_configs(self, tmp_path, mock_github_env):
        """Test installation with default_configs field."""
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
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
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.framework.utils.importlib.metadata.distributions") as mock_distributions,
            patch("cpex.framework.utils.importlib.util.find_spec") as mock_find_spec,
            patch("shutil.rmtree"),
        ):
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_dist.files = None  # No files attribute for non-isolated plugins
            mock_distributions.return_value = [mock_dist]
            
            # Setup mock spec for find_spec fallback
            mock_spec = Mock()
            mock_spec.origin = str(package_dir / "__init__.py")
            mock_find_spec.return_value = mock_spec
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            manifest, plugin_path = catalog.install_from_pypi("test_package")
            
            assert manifest.default_config == {"key": "value"}

    def test_install_from_pypi_with_existing_package_info(self, tmp_path, mock_github_env):
        """Test installation with existing package_info."""
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
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
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.framework.utils.importlib.metadata.distributions") as mock_distributions,
            patch("cpex.framework.utils.importlib.util.find_spec") as mock_find_spec,
            patch("shutil.rmtree"),
        ):
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_dist.files = None  # No files attribute for non-isolated plugins
            mock_distributions.return_value = [mock_dist]
            
            # Setup mock spec for find_spec fallback
            mock_spec = Mock()
            mock_spec.origin = str(package_dir / "__init__.py")
            mock_find_spec.return_value = mock_spec
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            manifest, plugin_path = catalog.install_from_pypi("test_package", ">=2.0.0")
            
            assert manifest.package_info is not None
            assert manifest.package_info.pypi_package == "test_package"
            assert manifest.package_info.version_constraint == ">=2.0.0"

    def test_install_from_pypi_with_null_default_configs_in_manifest(self, tmp_path, mock_github_env):
        """Test installation with null default_configs in manifest."""
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        package_dir = extract_dir / "test_package"
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
        
        with (
            patch("cpex.tools.catalog.PluginCatalog._download_package_to_temp", return_value=extract_dir),
            patch("cpex.tools.catalog.PluginCatalog._find_manifest_in_extracted_package", return_value=manifest_file),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.framework.utils.importlib.metadata.distributions") as mock_distributions,
            patch("cpex.framework.utils.importlib.util.find_spec") as mock_find_spec,
            patch("shutil.rmtree"),
        ):
            mock_dist = Mock()
            mock_dist.name = "test_package"
            mock_dist.files = None  # No files attribute for non-isolated plugins
            mock_distributions.return_value = [mock_dist]
            
            # Setup mock spec for find_spec fallback
            mock_spec = Mock()
            mock_spec.origin = str(package_dir / "__init__.py")
            mock_find_spec.return_value = mock_spec
            
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            manifest, plugin_path = catalog.install_from_pypi("test_package")
            
            # default_config should be empty dict when default_configs is None
            assert manifest.default_config == {}


# Made with Bob



class TestPluginCatalogProcessPyproject:
    """Tests for _process_pyproject helper method."""

    def test_process_pyproject_with_download_failure(self, tmp_path, mock_github_env):
        """Test _process_pyproject when download fails."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Mock the repository to raise exception
        mock_repo = Mock()
        mock_repo.get_contents = Mock(side_effect=Exception("Download failed"))
        
        item = Mock()
        item.name = "pyproject.toml"
        item.path = "plugin1/pyproject.toml"
        
        repo_url = httpx.URL("https://github.com/org/repo")
        headers = {}
        
        # Should raise exception
        with pytest.raises(Exception, match="Download failed"):
            catalog._process_pyproject(mock_repo, item, repo_url, headers)


class TestPluginCatalogUpdateCatalogWithPyprojectExtended:
    """Extended tests for update_catalog_with_pyproject method."""

    def test_update_catalog_with_pyproject_no_token(self, tmp_path, mock_github_env):
        """Test update_catalog_with_pyproject when no GitHub token is set."""
        with (
            patch("cpex.tools.catalog.logger") as mock_logger,
        ):
            catalog = PluginCatalog()
            catalog.github_token = None
            result = catalog.update_catalog_with_pyproject()
            
            assert result is True
            mock_logger.error.assert_called_with("No GitHub token set")

    def test_update_catalog_with_pyproject_repo_access_error(self, tmp_path, mock_github_env):
        """Test update_catalog_with_pyproject when repository access fails."""
        with (
            patch("cpex.tools.catalog.logger") as mock_logger,
        ):
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            catalog.monorepos = ["https://github.com/org/repo"]
            
            # Mock get_repo to raise exception
            catalog.gh.get_repo = Mock(side_effect=Exception("Access denied"))
            
            result = catalog.update_catalog_with_pyproject()
            
            assert result is False
            mock_logger.error.assert_called()

    def test_update_catalog_with_pyproject_search_error(self, tmp_path, mock_github_env):
        """Test update_catalog_with_pyproject when search fails."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            catalog.monorepos = ["https://github.com/org/repo"]
            
            # Mock successful get_repo but failing search
            mock_repo = Mock()
            catalog.gh.get_repo = Mock(return_value=mock_repo)
            catalog.gh.search_code = Mock(side_effect=Exception("Search failed"))
            
            result = catalog.update_catalog_with_pyproject()
            
            assert result is False
            mock_logger.error.assert_called()


class TestPluginCatalogSearchGithubCode:
    """Tests for _search_github_code method."""

    def test_search_github_code_exception(self, mock_github_env):
        """Test _search_github_code when exception occurs."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            
            # Mock search_code to raise exception
            catalog.gh.search_code = Mock(side_effect=Exception("Search error"))
            
            result = catalog._search_github_code("org/repo", "plugins", {})
            
            assert result is None
            mock_logger.error.assert_called()


class TestPluginCatalogProcessManifestItem:
    """Tests for _process_manifest_item method."""

    def test_process_manifest_item_not_yaml(self, tmp_path, mock_github_env):
        """Test _process_manifest_item with non-YAML file."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            item = {
                "name": "README.md",
                "path": "plugin1/README.md",
                "git_url": "https://api.github.com/file"
            }
            
            repo_url = httpx.URL("https://github.com/org/repo")
            relpath = tmp_path / "catalog" / "plugin1" / "plugin-manifest.yaml"
            mock_repo = Mock()
            result = catalog._process_manifest_item(item, "plugin1", "plugin1", repo_url, {}, relpath, "org/repo", gh_repo=mock_repo)
            
            assert result is False
            mock_logger.warning.assert_called()

    def test_process_manifest_item_download_failure(self, tmp_path, mock_github_env):
        """Test _process_manifest_item when download fails."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            # Mock download_file to return None
            catalog.download_file = Mock(return_value=None)
            
            item = {
                "name": "plugin-manifest.yaml",
                "path": "plugin1/plugin-manifest.yaml",
                "git_url": "https://api.github.com/file"
            }
            mock_repo = Mock()
            repo_url = httpx.URL("https://github.com/org/repo")
            relpath = tmp_path / "catalog" / "plugin1" / "plugin-manifest.yaml"
            
            result = catalog._process_manifest_item(item, "plugin1", "plugin1", repo_url, {}, relpath, "org/repo", gh_repo=mock_repo)
            
            assert result is False
            mock_logger.error.assert_called()


class TestPluginCatalogFindAndSavePluginManifestExtended:
    """Extended tests for find_and_save_plugin_manifest method."""

    def test_find_and_save_plugin_manifest_search_returns_none(self, tmp_path, mock_github_env):
        """Test find_and_save_plugin_manifest when search returns None."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Mock _search_github_code to return None
        catalog._search_github_code = Mock(return_value=None)
        mock_repo = Mock()
        repo_url = httpx.URL("https://github.com/org/repo")
        result = catalog.find_and_save_plugin_manifest("plugin1", "plugin1", repo_url, {}, mock_repo)
        
        assert result is None


class TestPluginCatalogVersionsJson:
    """Tests for versions.json discovery and download."""

    def test_search_github_code_for_versions_json_success(self, mock_github_env):
        """Test _search_github_code_for_versions_json filters versions.json files."""
        catalog = PluginCatalog()

        mock_search_result = Mock()
        matching_file = Mock()
        matching_file.name = "versions.json"
        matching_file.path = "plugin1/versions.json"
        matching_file.git_url = "https://api.github.com/repos/org/repo/git/blobs/versions"
        matching_file.html_url = "https://github.com/org/repo/blob/main/plugin1/versions.json"

        ignored_file = Mock()
        ignored_file.name = "plugin-manifest.yaml"
        ignored_file.path = "plugin1/plugin-manifest.yaml"
        ignored_file.git_url = "https://api.github.com/repos/org/repo/git/blobs/manifest"
        ignored_file.html_url = "https://github.com/org/repo/blob/main/plugin1/plugin-manifest.yaml"

        mock_search_result.totalCount = 2
        mock_search_result.__iter__ = Mock(return_value=iter([matching_file, ignored_file]))
        catalog.gh.search_code = Mock(return_value=mock_search_result)

        result = catalog._search_github_code_for_versions_json("org/repo", "plugin1", {})

        assert result == [
            {
                "name": "versions.json",
                "path": "plugin1/versions.json",
                "git_url": "https://api.github.com/repos/org/repo/git/blobs/versions",
                "html_url": "https://github.com/org/repo/blob/main/plugin1/versions.json",
            }
        ]
        catalog.gh.search_code.assert_called_once_with(
            query="repo:org/repo path:plugin1 filename:versions extension:json"
        )

    def test_search_github_code_for_versions_json_exception(self, mock_github_env):
        """Test _search_github_code_for_versions_json when exception occurs."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.gh.search_code = Mock(side_effect=Exception("Search error"))

            result = catalog._search_github_code_for_versions_json("org/repo", "plugin1", {})

            assert result is None
            mock_logger.error.assert_called()

    def test_find_and_save_plugin_versions_json_success(self, tmp_path, mock_github_env):
        """Test successful finding and saving of versions.json."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")

        mock_repo = Mock()
        repo_url = httpx.URL("https://github.com/org/repo")

        catalog._search_github_code_for_versions_json = Mock(
            return_value=[
                {
                    "name": "versions.json",
                    "path": "plugin1/versions.json",
                    "git_url": "https://api.github.com/repos/org/repo/git/blobs/versions",
                    "html_url": "https://github.com/org/repo/blob/main/plugin1/versions.json",
                }
            ]
        )

        versions_content = '{\n  "plugin1": [{"version": "1.0.0"}]\n}'
        catalog.download_file = Mock(return_value=versions_content)

        catalog.find_and_save_plugin_versions_json("plugin1", "plugin1", repo_url, {}, mock_repo)

        saved_file = tmp_path / "catalog" / "plugin1" / "versions.json"
        assert saved_file.exists()
        assert saved_file.read_text(encoding="utf-8") == versions_content

    def test_find_and_save_plugin_versions_json_search_returns_none(self, tmp_path, mock_github_env):
        """Test find_and_save_plugin_versions_json when search returns None."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog._search_github_code_for_versions_json = Mock(return_value=None)

        mock_repo = Mock()
        repo_url = httpx.URL("https://github.com/org/repo")

        result = catalog.find_and_save_plugin_versions_json("plugin1", "plugin1", repo_url, {}, mock_repo)

        assert result is None
        assert not (tmp_path / "catalog" / "plugin1" / "versions.json").exists()


class TestPluginCatalogLoadManifestFile:
    """Tests for _load_manifest_file method."""

    def test_load_manifest_file_not_found(self, tmp_path, mock_github_env):
        """Test _load_manifest_file when file doesn't exist."""
        catalog = PluginCatalog()
        manifest_path = tmp_path / "nonexistent" / "plugin-manifest.yaml"
        
        with pytest.raises(FileNotFoundError, match="plugin-manifest.yaml not found"):
            catalog._load_manifest_file(manifest_path)

    def test_load_manifest_file_invalid_yaml(self, tmp_path, mock_github_env):
        """Test _load_manifest_file with invalid YAML."""
        catalog = PluginCatalog()
        manifest_path = tmp_path / "plugin-manifest.yaml"
        manifest_path.write_text("invalid: yaml: content:")
        
        with pytest.raises(RuntimeError, match="Failed to parse manifest YAML"):
            catalog._load_manifest_file(manifest_path)

    def test_load_manifest_file_not_dict(self, tmp_path, mock_github_env):
        """Test _load_manifest_file when YAML is not a dictionary."""
        catalog = PluginCatalog()
        manifest_path = tmp_path / "plugin-manifest.yaml"
        manifest_path.write_text("- item1\n- item2")
        
        with pytest.raises(RuntimeError, match="Invalid manifest format"):
            catalog._load_manifest_file(manifest_path)


class TestPluginCatalogNormalizeManifestData:
    """Tests for _normalize_manifest_data method."""

    def test_normalize_manifest_data_validation_error(self, mock_github_env):
        """Test _normalize_manifest_data with validation error."""
        catalog = PluginCatalog()
        
        # Invalid manifest data (missing required fields)
        manifest_data = {"name": "test"}
        
        with pytest.raises(RuntimeError, match="Failed to validate manifest"):
            catalog._normalize_manifest_data(manifest_data, "test_package", None)


class TestPluginCatalogPersistManifest:
    """Tests for _persist_manifest method."""

    def test_persist_manifest_error(self, tmp_path, mock_github_env):
        """Test _persist_manifest when save fails."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "nonexistent" / "catalog")
        
        manifest = create_test_manifest()
        
        # Make directory read-only to cause save failure
        with patch("cpex.tools.catalog.PluginCatalog.save_manifest", side_effect=Exception("Save failed")):
            with pytest.raises(RuntimeError, match="Failed to save manifest"):
                catalog._persist_manifest(manifest, "test_plugin")


class TestPluginCatalogInstallPackage:
    """Tests for _install_package method."""

    def test_install_package_with_version_constraint(self, mock_github_env):
        """Test _install_package with version constraint."""
        with patch("cpex.tools.catalog.subprocess.run") as mock_subprocess:
            catalog = PluginCatalog()
            catalog._install_package("test_package", ">=1.0.0")
            
            mock_subprocess.assert_called_once()
            call_args = mock_subprocess.call_args[0][0]
            assert "test_package>=1.0.0" in " ".join(call_args)


class TestPluginCatalogDownloadFileExtended:
    """Extended tests for download_file method."""

    def test_download_file_with_exception_message(self, mock_github_env):
        """Test download_file logs proper error message."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            
            # Mock to raise exception
            catalog.gh.get_repo = Mock(side_effect=Exception("API error"))
            mock_repo = Mock()
            mock_repo.get_contents = Mock(side_effect=Exception("API error"))
            item = {"path": "test/file.yaml"}
            result = catalog.download_file("org/repo", item, {}, gh_repo=mock_repo)
            
            assert result is None
            # Check that error was logged with the item path
            assert mock_logger.error.called


class TestPluginCatalogSearchGithubCodeWithNullMember:
    """Tests for _search_github_code with member=None."""

    def test_search_github_code_with_null_member(self, mock_github_env):
        """Test _search_github_code when member is None."""
        catalog = PluginCatalog()
        
        # Mock the search results
        mock_search_results = MagicMock()
        mock_search_results.totalCount = 1
        
        mock_content_file = MagicMock()
        mock_content_file.name = "plugin-manifest.yaml"
        mock_content_file.path = "plugin-manifest.yaml"
        mock_content_file.git_url = "https://api.github.com/repos/org/repo/git/blobs/abc123"
        mock_content_file.html_url = "https://github.com/org/repo/blob/main/plugin-manifest.yaml"
        
        mock_search_results.__iter__ = Mock(return_value=iter([mock_content_file]))
        
        with patch.object(catalog.gh, 'search_code', return_value=mock_search_results):
            result = catalog._search_github_code("org/repo", None, {})
        
        assert result is not None
        assert len(result) == 1
        assert result[0]["name"] == "plugin-manifest.yaml"


class TestPluginCatalogTransformManifestDataWithNullMember:
    """Tests for _transform_manifest_data with member=None."""

    def test_transform_manifest_data_with_null_member(self, mock_github_env):
        """Test _transform_manifest_data when member is None."""
        catalog = PluginCatalog()
        
        manifest_content = {
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "available_hooks": ["tools"],
        }
        
        repo_url = httpx.URL("https://github.com/org/repo")
        result = catalog._transform_manifest_data(manifest_content, "test_plugin", None, repo_url)
        
        assert result["name"] == "test_plugin"
        assert result["monorepo"]["package_source"] == "https://github.com/org/repo"
        assert result["monorepo"]["package_folder"] == ""


class TestPluginCatalogDownloadMonorepoFolderToTemp:
    """Tests for _download_monorepo_folder_to_temp method."""

    def test_download_monorepo_folder_success(self, tmp_path, mock_github_env):
        """Test successful download of monorepo folder."""
        catalog = PluginCatalog()
        
        # Create a mock tarball
        mock_tarball = tmp_path / "package.tar.gz"
        with tarfile.open(mock_tarball, "w:gz") as tar:
            # Create a temporary file to add to the tarball
            temp_file = tmp_path / "test_file.txt"
            temp_file.write_text("test content")
            tar.add(temp_file, arcname="test_file.txt")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = [mock_tarball]
                
                result = catalog._download_monorepo_folder_to_temp(
                    "git+https://github.com/org/repo#subdirectory=plugin",
                    "test_plugin"
                )
                
                assert result.exists()
                assert result.name == "extracted"

    def test_download_monorepo_folder_no_files(self, tmp_path, mock_github_env):
        """Test error when no files are downloaded."""
        catalog = PluginCatalog()
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = []
                
                with pytest.raises(RuntimeError) as exc_info:
                    catalog._download_monorepo_folder_to_temp(
                        "git+https://github.com/org/repo#subdirectory=plugin",
                        "test_plugin"
                    )
                
                assert "No files downloaded" in str(exc_info.value)

    def test_download_monorepo_folder_unsupported_format(self, tmp_path, mock_github_env):
        """Test error with unsupported package format."""
        catalog = PluginCatalog()
        
        # Create a mock file with unsupported extension
        mock_file = tmp_path / "package.unknown"
        mock_file.write_text("test")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = [mock_file]
                
                with pytest.raises(RuntimeError) as exc_info:
                    catalog._download_monorepo_folder_to_temp(
                        "git+https://github.com/org/repo#subdirectory=plugin",
                        "test_plugin"
                    )
                
                assert "Unsupported package format" in str(exc_info.value)

    def test_download_monorepo_folder_subprocess_error(self, mock_github_env):
        """Test subprocess error handling."""
        catalog = PluginCatalog()
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "pip", stderr="Download failed")
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog._download_monorepo_folder_to_temp(
                    "git+https://github.com/org/repo#subdirectory=plugin",
                    "test_plugin"
                )
            
            assert "Failed to download" in str(exc_info.value)


class TestPluginCatalogDownloadPackageToTemp:
    """Tests for _download_package_to_temp method."""

    def test_download_package_with_test_pypi(self, tmp_path, mock_github_env):
        """Test downloading from test.pypi.org."""
        catalog = PluginCatalog()
        
        # Create a mock wheel file
        mock_wheel = tmp_path / "package-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(mock_wheel, "w") as zf:
            zf.writestr("test_file.txt", "test content")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = [mock_wheel]
                
                result = catalog._download_package_to_temp("test_plugin", None, use_test=True)
                
                assert result.exists()
                assert result.name == "extracted"
                
                # Verify test.pypi.org was used
                call_args = mock_run.call_args[0][0]
                assert "--index-url" in call_args
                assert "https://test.pypi.org/simple/" in call_args

    def test_download_package_no_files_downloaded(self, mock_github_env):
        """Test error when no files are downloaded."""
        catalog = PluginCatalog()
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = []
                
                with pytest.raises(RuntimeError) as exc_info:
                    catalog._download_package_to_temp("test_plugin", None)
                
                assert "No files downloaded" in str(exc_info.value)

    def test_download_package_unsupported_format(self, tmp_path, mock_github_env):
        """Test error with unsupported package format."""
        catalog = PluginCatalog()
        
        mock_file = tmp_path / "package.exe"
        mock_file.write_text("test")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = [mock_file]
                
                with pytest.raises(RuntimeError) as exc_info:
                    catalog._download_package_to_temp("test_plugin", None)
                
                assert "Unsupported package format" in str(exc_info.value)


class TestPluginCatalogFindManifestInExtractedPackage:
    """Tests for _find_manifest_in_extracted_package method."""

    def test_find_manifest_not_found(self, tmp_path, mock_github_env):
        """Test FileNotFoundError when manifest is not found."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        with pytest.raises(FileNotFoundError) as exc_info:
            catalog._find_manifest_in_extracted_package(extract_dir, "test_plugin")
        
        assert "plugin-manifest.yaml not found" in str(exc_info.value)


class TestPluginCatalogUninstallPackage:
    """Tests for uninstall_package method."""

    def test_uninstall_package_success_native(self, mock_github_env):
        """Test successful package uninstallation for native plugin."""
        catalog = PluginCatalog()
        
        # Create a native plugin manifest
        manifest = create_test_manifest(kind="native")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            result = catalog.uninstall_package("test_plugin", manifest)
            
            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "pip" in call_args
            assert "uninstall" in call_args
            assert "-y" in call_args
            assert "test_plugin" in call_args
            # Should use current python executable for native plugins
            assert call_args[0] == catalog.python_executable

    def test_uninstall_package_success_isolated_venv(self, tmp_path, mock_github_env):
        """Test successful package uninstallation for isolated_venv plugin."""
        catalog = PluginCatalog()
        catalog.plugin_folder = str(tmp_path / "plugins")
        
        # Create an isolated_venv plugin manifest
        manifest = create_test_manifest(kind="isolated_venv")
        
        # Create mock venv structure
        plugin_path = tmp_path / "plugins" / "test_plugin"
        plugin_path.mkdir(parents=True)
        venv_path = plugin_path / ".venv"
        venv_bin = venv_path / "bin"
        venv_bin.mkdir(parents=True)
        venv_python = venv_bin / "python"
        venv_python.touch()
        
        # Mock the IsolatedVenvPlugin
        mock_isolated_plugin = MagicMock()
        mock_isolated_plugin.plugin_path = plugin_path
        
        with (
            patch('subprocess.run') as mock_run,
            patch('cpex.framework.isolated.client.IsolatedVenvPlugin', return_value=mock_isolated_plugin),
            patch.object(catalog, '_get_venv_python_executable', return_value=str(venv_python)),
        ):
            mock_run.return_value = MagicMock(returncode=0)
            
            result = catalog.uninstall_package("test_plugin", manifest)
            
            assert result is True
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "pip" in call_args
            assert "uninstall" in call_args
            assert "-y" in call_args
            assert "test_plugin" in call_args
            # Should use venv python executable for isolated plugins
            assert call_args[0] == str(venv_python)

    def test_uninstall_package_subprocess_error(self, mock_github_env):
        """Test subprocess error during uninstallation."""
        catalog = PluginCatalog()
        manifest = create_test_manifest(kind="native")
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "pip", stderr="Uninstall failed")
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog.uninstall_package("test_plugin", manifest)
            
            assert "Failed to uninstall" in str(exc_info.value)

    def test_uninstall_package_unexpected_error(self, mock_github_env):
        """Test unexpected error during uninstallation."""
        catalog = PluginCatalog()
        manifest = create_test_manifest(kind="native")
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Unexpected error")
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog.uninstall_package("test_plugin", manifest)
            
            assert "Unexpected error uninstalling" in str(exc_info.value)

    def test_uninstall_package_isolated_venv_error(self, tmp_path, mock_github_env):
        """Test error during isolated_venv plugin uninstallation."""
        catalog = PluginCatalog()
        catalog.plugin_folder = str(tmp_path / "plugins")
        manifest = create_test_manifest(kind="isolated_venv")
        
        # Create mock venv structure
        plugin_path = tmp_path / "plugins" / "test_plugin"
        plugin_path.mkdir(parents=True)
        venv_path = plugin_path / ".venv"
        venv_bin = venv_path / "bin"
        venv_bin.mkdir(parents=True)
        venv_python = venv_bin / "python"
        venv_python.touch()
        
        # Mock the IsolatedVenvPlugin
        mock_isolated_plugin = MagicMock()
        mock_isolated_plugin.plugin_path = plugin_path
        
        with (
            patch('subprocess.run') as mock_run,
            patch('cpex.framework.isolated.client.IsolatedVenvPlugin', return_value=mock_isolated_plugin),
            patch.object(catalog, '_get_venv_python_executable', return_value=str(venv_python)),
        ):
            mock_run.side_effect = subprocess.CalledProcessError(1, "pip", stderr="Uninstall failed")
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog.uninstall_package("test_plugin", manifest)
            
            assert "Failed to uninstall" in str(exc_info.value)


class TestPluginCatalogInstallFolderViaPipIsolated:
    """Tests for install_folder_via_pip with isolated_venv plugins."""

    def test_install_folder_via_pip_isolated_venv(self, tmp_path, mock_github_env):
        """Test installing an isolated_venv plugin from monorepo."""
        catalog = PluginCatalog()
        
        manifest = create_test_manifest(kind="isolated_venv")
        
        # Mock the download and initialization
        with patch.object(catalog, '_download_monorepo_folder_to_temp') as mock_download:
            mock_download.return_value = tmp_path / "package"
            
            with patch.object(catalog, '_initialize_isolated_venv') as mock_init:
                mock_init.return_value = tmp_path / "venv"
                
                result = catalog.install_folder_via_pip(manifest)
                
                assert result == tmp_path / "venv"
                mock_download.assert_called_once()
                mock_init.assert_called_once()



class TestPluginCatalogProcessPyprojectExtended:
    """Extended tests for _process_pyproject method."""

    def test_process_pyproject_with_member_none(self, mock_github_env):
        """Test _process_pyproject when member is None (root directory)."""
        catalog = PluginCatalog()
        
        mock_repo = MagicMock()
        mock_item = MagicMock()
        mock_item.path = "pyproject.toml"
        mock_item.name = "pyproject.toml"
        
        # Mock file content
        pyproject_content = """
[project]
name = "test_plugin"
version = "1.0.0"
"""
        mock_file_content = MagicMock()
        mock_file_content.decoded_content = pyproject_content.encode('utf-8')
        mock_repo.get_contents.return_value = mock_file_content
        
        repo_url = httpx.URL("https://github.com/org/repo")
        
        with patch.object(catalog, 'find_and_save_plugin_manifest') as mock_find:
            catalog._process_pyproject(mock_repo, mock_item, repo_url, {})
            
            # Verify find_and_save_plugin_manifest was called with member=None
            mock_find.assert_called_once()
            call_args = mock_find.call_args
            assert call_args[1]['member'] is None


class TestPluginCatalogInstallFolderViaPipNonIsolated:
    """Tests for install_folder_via_pip with non-isolated plugins."""

    def test_install_folder_via_pip_non_isolated(self, mock_github_env):
        """Test installing a non-isolated plugin from monorepo."""
        catalog = PluginCatalog()
        
        manifest = create_test_manifest(kind="native")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            result = catalog.install_folder_via_pip(manifest)
            
            # For non-isolated plugins, should return None
            assert result is None
            
            # Verify pip install was called
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "pip" in call_args
            assert "install" in call_args


class TestPluginCatalogInstallPackageEdgeCases:
    """Edge case tests for _install_package method."""

    def test_install_package_with_null_version_constraint(self, mock_github_env):
        """Test installing package with None version constraint."""
        catalog = PluginCatalog()
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            catalog._install_package("test_plugin", None, use_test=False)
            
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "test_plugin" in call_args
            assert "--index-url" not in call_args

    def test_install_package_unexpected_error(self, mock_github_env):
        """Test unexpected error during package installation."""
        catalog = PluginCatalog()
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Unexpected error")
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog._install_package("test_plugin", None)
            
            assert "Unexpected error installing" in str(exc_info.value)


class TestPluginCatalogDownloadPackageEdgeCases:
    """Edge case tests for download methods."""

    def test_download_package_with_version_constraint(self, tmp_path, mock_github_env):
        """Test downloading package with version constraint."""
        catalog = PluginCatalog()
        
        mock_wheel = tmp_path / "package-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(mock_wheel, "w") as zf:
            zf.writestr("test_file.txt", "test content")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = [mock_wheel]
                
                result = catalog._download_package_to_temp("test_plugin", ">=1.0.0", use_test=False)
                
                assert result.exists()
                
                # Verify version constraint was included
                call_args = mock_run.call_args[0][0]
                assert any("test_plugin>=1.0.0" in str(arg) for arg in call_args)

    def test_download_monorepo_zip_format(self, tmp_path, mock_github_env):
        """Test downloading monorepo with zip format."""
        catalog = PluginCatalog()
        
        # Create a mock zip file
        mock_zip = tmp_path / "package.zip"
        with zipfile.ZipFile(mock_zip, "w") as zf:
            zf.writestr("test_file.txt", "test content")
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            with patch('pathlib.Path.glob') as mock_glob:
                mock_glob.return_value = [mock_zip]
                
                result = catalog._download_monorepo_folder_to_temp(
                    "git+https://github.com/org/repo#subdirectory=plugin",
                    "test_plugin"
                )
                
                assert result.exists()
                assert result.name == "extracted"


class TestPluginCatalogFindOperations:
    """Tests for find method."""

    def test_find_case_insensitive(self, tmp_path, mock_github_env):
        """Test that find is case-insensitive."""
        catalog = PluginCatalog()
        
        # Create a manifest with uppercase name
        manifest_dir = tmp_path / "catalog" / "TEST_PLUGIN"
        manifest_dir.mkdir(parents=True)
        manifest_file = manifest_dir / "plugin-manifest.yaml"
        
        manifest_data = {
            "name": "TEST_PLUGIN",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "available_hooks": ["tools"],
            "tags": [],
            "default_config": {},
        }
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.load()
        
        # Search with lowercase should find it
        result = catalog.find("test_plugin")
        
        assert result is not None
        assert result.name == "TEST_PLUGIN"


class TestPluginCatalogInstallFromPypiIsolated:
    """Tests for install_from_pypi with isolated_venv plugins."""

    def test_install_from_pypi_isolated_venv(self, tmp_path, mock_github_env):
        """Test installing an isolated_venv plugin from PyPI."""
        catalog = PluginCatalog()
        
        # Create mock extracted package with manifest
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "isolated_venv",
            "description": "Test isolated plugin",
            "author": "Test Author",
            "available_hooks": ["tools"],
            "default_config": {"requirements_file": "requirements.txt"},
        }
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with patch.object(catalog, '_download_package_to_temp') as mock_download:
            mock_download.return_value = extract_dir
            
            with patch.object(catalog, '_initialize_isolated_venv') as mock_init:
                mock_init.return_value = tmp_path / "venv"
                
                with patch.object(catalog, '_persist_manifest'):
                    manifest, plugin_path = catalog.install_from_pypi("test_plugin")
                    
                    assert manifest.kind == "isolated_venv"
                    assert plugin_path == tmp_path / "venv"
                    mock_init.assert_called_once()



class TestPluginCatalogFindRequirementsInExtractedPackage:
    """Tests for _find_requirements_in_extracted_package method with path traversal protection."""

    def test_find_requirements_success(self, tmp_path, mock_github_env):
        """Test successful finding of requirements file."""
        catalog = PluginCatalog()
        
        # Create a mock extracted package directory with requirements.txt
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "my_plugin"
        plugin_dir.mkdir()
        requirements_file = plugin_dir / "requirements.txt"
        requirements_file.write_text("pytest>=7.0.0\n")
        
        # Find the requirements file
        result = catalog._find_requirements_in_extracted_package(
            extract_dir, "my_plugin", "requirements.txt"
        )
        
        assert result == requirements_file
        assert result.exists()

    def test_find_requirements_not_found(self, tmp_path, mock_github_env):
        """Test FileNotFoundError when requirements file doesn't exist."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        with pytest.raises(FileNotFoundError) as exc_info:
            catalog._find_requirements_in_extracted_package(
                extract_dir, "my_plugin", "requirements.txt"
            )
        
        assert "requirements file requirements.txt not found" in str(exc_info.value)
        assert "my_plugin" in str(exc_info.value)

    def test_find_requirements_path_traversal_parent_directory(self, tmp_path, mock_github_env):
        """Test that path traversal with ../ is blocked."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        # Try to access parent directory
        with pytest.raises(ValueError) as exc_info:
            catalog._find_requirements_in_extracted_package(
                extract_dir, "my_plugin", "../../../etc/passwd"
            )
        
        assert "path traversal attempts are not allowed" in str(exc_info.value)

    def test_find_requirements_path_traversal_absolute_path(self, tmp_path, mock_github_env):
        """Test that absolute paths are blocked."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        # Try to use absolute path
        with pytest.raises(ValueError) as exc_info:
            catalog._find_requirements_in_extracted_package(
                extract_dir, "my_plugin", "/etc/passwd"
            )
        
        assert "path traversal attempts are not allowed" in str(exc_info.value)

    def test_find_requirements_path_traversal_mixed_separators(self, tmp_path, mock_github_env):
        """Test that mixed path separators are blocked."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        # Try to use backslashes (Windows-style) in suspicious way
        with pytest.raises(ValueError) as exc_info:
            catalog._find_requirements_in_extracted_package(
                extract_dir, "my_plugin", "..\\..\\etc\\passwd"
            )
        
        assert "path traversal attempts are not allowed" in str(exc_info.value)

    def test_find_requirements_path_traversal_encoded(self, tmp_path, mock_github_env):
        """Test that URL-encoded path traversal attempts are blocked."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        # Try various encoded forms
        malicious_paths = [
            "..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5cetc%5cpasswd",
        ]
        
        for malicious_path in malicious_paths:
            with pytest.raises(ValueError) as exc_info:
                catalog._find_requirements_in_extracted_package(
                    extract_dir, "my_plugin", malicious_path
                )
            
            assert "path traversal" in str(exc_info.value).lower() or "suspicious" in str(exc_info.value).lower()

    def test_find_requirements_defense_in_depth(self, tmp_path, mock_github_env):
        """Test defense-in-depth check that file is within extract_dir."""
        catalog = PluginCatalog()
        
        # Create extract directory
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        # Create a file outside the extract directory
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "requirements.txt"
        outside_file.write_text("malicious\n")
        
        # Create a symlink inside extract_dir pointing outside
        # (This tests the defense-in-depth check)
        try:
            symlink_path = extract_dir / "requirements.txt"
            symlink_path.symlink_to(outside_file)
            
            # The rglob should find it, but the defense-in-depth check should catch it
            with pytest.raises(ValueError) as exc_info:
                catalog._find_requirements_in_extracted_package(
                    extract_dir, "my_plugin", "requirements.txt"
                )
            
            assert "outside the package directory" in str(exc_info.value)
        except OSError:
            # Skip test if symlinks aren't supported (e.g., Windows without admin)
            pytest.skip("Symlinks not supported on this system")

    def test_find_requirements_nested_directory(self, tmp_path, mock_github_env):
        """Test finding requirements file in nested directory structure."""
        catalog = PluginCatalog()
        
        # Create nested directory structure
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        nested_dir = extract_dir / "plugin" / "subdir" / "config"
        nested_dir.mkdir(parents=True)
        requirements_file = nested_dir / "requirements.txt"
        requirements_file.write_text("pytest>=7.0.0\n")
        
        # Should find the file in nested structure
        result = catalog._find_requirements_in_extracted_package(
            extract_dir, "my_plugin", "requirements.txt"
        )
        
        assert result == requirements_file
        assert result.exists()

    def test_find_requirements_multiple_files_returns_first(self, tmp_path, mock_github_env):
        """Test that when multiple matching files exist, the first one is returned."""
        catalog = PluginCatalog()
        
        # Create multiple requirements files
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        
        dir1 = extract_dir / "dir1"
        dir1.mkdir()
        req1 = dir1 / "requirements.txt"
        req1.write_text("first\n")
        
        dir2 = extract_dir / "dir2"
        dir2.mkdir()
        req2 = dir2 / "requirements.txt"
        req2.write_text("second\n")
        
        # Should return one of them (first found by rglob)
        result = catalog._find_requirements_in_extracted_package(
            extract_dir, "my_plugin", "requirements.txt"
        )
        
        assert result in [req1, req2]
        assert result.exists()

    def test_find_requirements_custom_filename(self, tmp_path, mock_github_env):
        """Test finding a custom requirements filename."""
        catalog = PluginCatalog()
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "my_plugin"
        plugin_dir.mkdir()
        
        # Use a custom requirements filename
        custom_req = plugin_dir / "requirements-dev.txt"
        custom_req.write_text("pytest>=7.0.0\n")
        
        result = catalog._find_requirements_in_extracted_package(
            extract_dir, "my_plugin", "requirements-dev.txt"
        )
        
        assert result == custom_req
        assert result.exists()


class TestPluginCatalogFindAndLoadVersionsJson:
    """Tests for _find_and_load_versions_json method."""

    def test_find_and_load_versions_json_non_isolated_success(self, tmp_path, mock_github_env):
        """Test _find_and_load_versions_json for non-isolated plugin with versions.json."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create a plugin path with versions.json
        plugin_path = tmp_path / "plugin_package"
        plugin_path.mkdir()
        versions_json = plugin_path / "versions.json"
        versions_data = {"versions": [{"version": "1.0.0", "date": "2024-01-01"}]}
        versions_json.write_text(json.dumps(versions_data))
        
        manifest = create_test_manifest(name="test_plugin", kind="native")
        
        catalog._find_and_load_versions_json(manifest, plugin_path, "test_plugin")
        
        # Check that versions.json was saved to catalog
        catalog_versions = Path(catalog.catalog_folder) / "test_plugin" / "versions.json"
        assert catalog_versions.exists()
        saved_data = json.loads(catalog_versions.read_text())
        assert saved_data == versions_data

    def test_find_and_load_versions_json_non_isolated_no_file(self, tmp_path, mock_github_env):
        """Test _find_and_load_versions_json for non-isolated plugin without versions.json."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            # Create a plugin path without versions.json
            plugin_path = tmp_path / "plugin_package"
            plugin_path.mkdir()
            
            manifest = create_test_manifest(name="test_plugin", kind="native")
            
            catalog._find_and_load_versions_json(manifest, plugin_path, "test_plugin")
            
            # Check that no versions.json was saved to catalog
            catalog_versions = Path(catalog.catalog_folder) / "test_plugin" / "versions.json"
            assert not catalog_versions.exists()
            mock_logger.debug.assert_called()

    def test_find_and_load_versions_json_isolated_success(self, tmp_path, mock_github_env):
        """Test _find_and_load_versions_json for isolated_venv plugin."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create a venv path
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        
        # Mock the subprocess call to find package path
        mock_package_path = tmp_path / "venv_package"
        mock_package_path.mkdir()
        versions_json = mock_package_path / "versions.json"
        versions_data = {"versions": [{"version": "2.0.0", "date": "2024-02-01"}]}
        versions_json.write_text(json.dumps(versions_data))
        
        manifest = create_test_manifest(name="test_plugin", kind="isolated_venv")
        
        with (
            patch.object(catalog, "_get_venv_python_executable", return_value="/fake/python"),
            patch("cpex.tools.catalog.subprocess.run") as mock_run,
        ):
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = str(mock_package_path)
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            catalog._find_and_load_versions_json(manifest, venv_path, "test_plugin")
        
        # Check that versions.json was saved to catalog
        catalog_versions = Path(catalog.catalog_folder) / "test_plugin" / "versions.json"
        assert catalog_versions.exists()
        saved_data = json.loads(catalog_versions.read_text())
        assert saved_data == versions_data

    def test_find_and_load_versions_json_isolated_subprocess_failure(self, tmp_path, mock_github_env):
        """Test _find_and_load_versions_json for isolated_venv when subprocess fails."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            venv_path = tmp_path / ".venv"
            venv_path.mkdir()
            
            manifest = create_test_manifest(name="test_plugin", kind="isolated_venv")
            
            with patch("cpex.tools.catalog.subprocess.run") as mock_run:
                mock_result = Mock()
                mock_result.returncode = 1
                mock_result.stdout = ""
                mock_result.stderr = "NOT_FOUND"
                mock_run.return_value = mock_result
                
                catalog._find_and_load_versions_json(manifest, venv_path, "test_plugin")
            
            # Check that no versions.json was saved
            catalog_versions = Path(catalog.catalog_folder) / "test_plugin" / "versions.json"
            assert not catalog_versions.exists()
            mock_logger.warning.assert_called()

    def test_find_and_load_versions_json_none_plugin_path(self, tmp_path, mock_github_env):
        """Test _find_and_load_versions_json with None plugin_path."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        manifest = create_test_manifest(name="test_plugin", kind="native")
        
        # Should handle None gracefully
        catalog._find_and_load_versions_json(manifest, None, "test_plugin")
        
        catalog_versions = Path(catalog.catalog_folder) / "test_plugin" / "versions.json"
        assert not catalog_versions.exists()

    def test_find_and_load_versions_json_exception_handling(self, tmp_path, mock_github_env):
        """Test _find_and_load_versions_json handles exceptions gracefully."""
        with patch("cpex.tools.catalog.logger") as mock_logger:
            catalog = PluginCatalog()
            catalog.catalog_folder = str(tmp_path / "catalog")
            
            plugin_path = tmp_path / "plugin_package"
            plugin_path.mkdir()
            
            manifest = create_test_manifest(name="test_plugin", kind="native")
            
            # Create a versions.json that will cause an error when reading
            versions_json = plugin_path / "versions.json"
            versions_json.write_text("invalid json {{{")
            
            catalog._find_and_load_versions_json(manifest, plugin_path, "test_plugin")
            
            mock_logger.warning.assert_called()


class TestPluginCatalogGetVenvPythonExecutable:
    """Tests for _get_venv_python_executable method."""

    def test_get_venv_python_executable_unix(self, tmp_path, mock_github_env):
        """Test _get_venv_python_executable on Unix-like systems."""
        catalog = PluginCatalog()
        
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        bin_dir = venv_path / "bin"
        bin_dir.mkdir()
        python_exe = bin_dir / "python"
        python_exe.touch()
        
        with patch("sys.platform", "linux"):
            result = catalog._get_venv_python_executable(venv_path)
            assert result == str(python_exe)

    def test_get_venv_python_executable_windows(self, tmp_path, mock_github_env):
        """Test _get_venv_python_executable on Windows."""
        catalog = PluginCatalog()
        
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        scripts_dir = venv_path / "Scripts"
        scripts_dir.mkdir()
        python_exe = scripts_dir / "python.exe"
        python_exe.touch()
        
        with patch("sys.platform", "win32"):
            result = catalog._get_venv_python_executable(venv_path)
            assert result == str(python_exe)

    def test_get_venv_python_executable_not_found(self, tmp_path, mock_github_env):
        """Test _get_venv_python_executable when executable doesn't exist."""
        catalog = PluginCatalog()
        
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        
        with pytest.raises(FileNotFoundError, match="Python executable not found"):
            catalog._get_venv_python_executable(venv_path)


class TestPluginCatalogInstallFromPypiWithVersionsJson:
    """Tests for install_from_pypi integration with versions.json."""

    def test_install_from_pypi_calls_find_and_load_versions_json(self, tmp_path, mock_github_env):
        """Test that install_from_pypi calls _find_and_load_versions_json."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create temporary package structure
        temp_extract = tmp_path / "temp_extract"
        temp_extract.mkdir()
        package_dir = temp_extract / "test_plugin"
        package_dir.mkdir()
        
        manifest_path = package_dir / "plugin-manifest.yaml"
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test",
            "author": "Test",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {}
        }
        manifest_path.write_text(yaml.dump(manifest_data))
        
        with (
            patch.object(catalog, "_download_package_to_temp", return_value=temp_extract),
            patch.object(catalog, "_install_package"),
            patch("cpex.tools.catalog.find_package_path", return_value=package_dir),
            patch.object(catalog, "_find_and_load_versions_json") as mock_find_versions,
            patch.object(catalog, "update_plugin_version_registry"),
        ):
            manifest, plugin_path = catalog.install_from_pypi("test_plugin")
            
            # Verify _find_and_load_versions_json was called
            mock_find_versions.assert_called_once()
            call_args = mock_find_versions.call_args
            assert call_args[0][0].name == "test_plugin"  # manifest
            assert call_args[0][1] == package_dir  # plugin_path
            assert call_args[0][2] == "test_plugin"  # package_name


# Made with Bob


class TestPluginCatalogInstallFromLocal:
    """Tests for PluginCatalog.install_from_local method."""

    def test_install_from_local_manifest_in_root(self, tmp_path, mock_github_env):
        """Test installing from local source with manifest in root directory."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create source directory with pyproject and manifest in root
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.find_package_path", return_value=source_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=source_dir),
            patch.object(catalog, "update_plugin_version_registry"),
        ):
            manifest, plugin_path = catalog.install_from_local(source_dir)
            
            # Verify subprocess was called with pip install -e
            mock_subprocess.assert_called_once()
            call_args = mock_subprocess.call_args[0][0]
            assert "-m" in call_args
            assert "pip" in call_args
            assert "install" in call_args
            assert "-e" in call_args
            assert str(source_dir) in call_args
            
            assert manifest.name == "my_plugin"
            assert manifest.kind == "native"
            assert plugin_path == source_dir

    def test_install_from_local_manifest_in_subdirectory(self, tmp_path, mock_github_env):
        """Test installing from local source with manifest in subdirectory."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create source directory with pyproject and manifest in subdirectory
        source_dir = tmp_path / "my_plugin_project"
        source_dir.mkdir()
        plugin_subdir = source_dir / "my_plugin"
        plugin_subdir.mkdir()
        (plugin_subdir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_subdir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.find_package_path", return_value=source_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=source_dir),
            patch.object(catalog, "update_plugin_version_registry"),
        ):
            manifest, plugin_path = catalog.install_from_local(source_dir)
            
            assert manifest.name == "my_plugin"
            mock_subprocess.assert_called_once()

    def test_install_from_local_manifest_not_found(self, tmp_path, mock_github_env):
        """Test error when manifest is not found in source or subdirectories."""
        catalog = PluginCatalog()
        
        # Create source directory without pyproject or manifest
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        
        with pytest.raises(FileNotFoundError, match="pyproject.toml not found"):
            catalog.install_from_local(source_dir)

    def test_install_from_local_isolated_venv(self, tmp_path, mock_github_env):
        """Test installing an isolated_venv plugin from local source."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.plugin_folder = str(tmp_path / "plugins")
        
        # Create source directory with isolated_venv pyproject and manifest
        source_dir = tmp_path / "my_isolated_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_isolated_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_isolated_plugin",
            "version": "1.0.0",
            "kind": "isolated_venv",
            "description": "Test isolated plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {"requirements_file": "requirements.txt"},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        # Mock IsolatedVenvPlugin
        mock_isolated_plugin = Mock()
        mock_isolated_plugin.plugin_path = tmp_path / "plugins" / "my_isolated_plugin"
        mock_isolated_plugin.plugin_path.mkdir(parents=True, exist_ok=True)
        venv_path = mock_isolated_plugin.plugin_path / ".venv"
        venv_path.mkdir(parents=True, exist_ok=True)
        
        # Create mock venv python executable
        if sys.platform == "win32":
            python_exe = venv_path / "Scripts" / "python.exe"
        else:
            python_exe = venv_path / "bin" / "python"
        python_exe.parent.mkdir(parents=True, exist_ok=True)
        python_exe.touch()
        
        with (
            patch("cpex.framework.isolated.client.IsolatedVenvPlugin", return_value=mock_isolated_plugin),
            patch("asyncio.run"),
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=mock_isolated_plugin.plugin_path),
            patch.object(catalog, "update_plugin_version_registry"),
        ):
            manifest, plugin_path = catalog.install_from_local(source_dir)
            
            # Verify subprocess was called with venv python
            mock_subprocess.assert_called_once()
            call_args = mock_subprocess.call_args[0][0]
            assert str(python_exe) == call_args[0]
            assert "-m" in call_args
            assert "pip" in call_args
            assert "install" in call_args
            assert "-e" in call_args
            assert str(source_dir) in call_args
            
            assert manifest.name == "my_isolated_plugin"
            assert manifest.kind == "isolated_venv"
            assert plugin_path == mock_isolated_plugin.plugin_path

    def test_install_from_local_subprocess_error(self, tmp_path, mock_github_env):
        """Test error handling when pip install fails."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create source directory with pyproject and manifest
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with patch("cpex.tools.catalog.subprocess.run") as mock_subprocess:
            mock_subprocess.side_effect = subprocess.CalledProcessError(
                1, ["pip", "install"], stderr="Installation failed"
            )
            
            with pytest.raises(RuntimeError, match="Failed to install plugin from"):
                catalog.install_from_local(source_dir)

    def test_install_from_local_invalid_manifest(self, tmp_path, mock_github_env):
        """Test error handling when manifest is invalid."""
        catalog = PluginCatalog()
        
        # Create source directory with pyproject and invalid manifest
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text("invalid: yaml: content:")
        
        with pytest.raises(RuntimeError, match="Failed to parse manifest YAML"):
            catalog.install_from_local(source_dir)

    def test_install_from_local_calls_persist_and_registry(self, tmp_path, mock_github_env):
        """Test that install_from_local calls persist_manifest and update_plugin_version_registry."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create source directory with pyproject and manifest
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with (
            patch("cpex.tools.catalog.subprocess.run"),
            patch("cpex.tools.catalog.find_package_path", return_value=source_dir),
            patch.object(catalog, "_persist_manifest") as mock_persist,
            patch.object(catalog, "_find_and_load_versions_json", return_value=source_dir) as mock_versions,
            patch.object(catalog, "update_plugin_version_registry") as mock_registry,
        ):
            manifest, plugin_path = catalog.install_from_local(source_dir)
            
            # Verify all post-install steps were called
            mock_persist.assert_called_once()
            mock_versions.assert_called_once()
            mock_registry.assert_called_once()
            
            # Verify the manifest was passed correctly
            persist_call_args = mock_persist.call_args[0]
            assert persist_call_args[0].name == "my_plugin"

    def test_install_from_local_isolated_venv_initialization_error(self, tmp_path, mock_github_env):
        """Test error handling when isolated venv initialization fails."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        catalog.plugin_folder = str(tmp_path / "plugins")
        
        # Create source directory with isolated_venv pyproject and manifest
        source_dir = tmp_path / "my_isolated_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_isolated_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_isolated_plugin",
            "version": "1.0.0",
            "kind": "isolated_venv",
            "description": "Test isolated plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {"requirements_file": "requirements.txt"},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with (
            patch("cpex.framework.isolated.client.IsolatedVenvPlugin") as mock_plugin_class,
            patch("asyncio.run") as mock_asyncio_run,
        ):
            mock_asyncio_run.side_effect = Exception("Venv initialization failed")
            
            with pytest.raises(RuntimeError, match="Failed to install isolated_venv plugin"):
                catalog.install_from_local(source_dir)

    def test_install_from_local_fallback_to_source_path(self, tmp_path, mock_github_env):
        """Test that source path is used as fallback when find_package_path returns None."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create source directory with pyproject and manifest
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        with (
            patch("cpex.tools.catalog.subprocess.run"),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=None),
            patch.object(catalog, "update_plugin_version_registry"),
        ):
            manifest, plugin_path = catalog.install_from_local(source_dir)
            
            # Non-isolated installs now derive plugin_path from manifest location
            assert plugin_path == source_dir

    def test_install_from_local_with_versions_json(self, tmp_path, mock_github_env):
        """Test that versions.json is found and loaded correctly."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create source directory with pyproject and manifest
        source_dir = tmp_path / "my_plugin"
        source_dir.mkdir()
        (source_dir / "pyproject.toml").write_text('[project]\nname = "my_plugin"\nversion = "1.0.0"\n')
        
        manifest_data = {
            "name": "my_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = source_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        # Create a different path that versions.json returns
        actual_path = tmp_path / "actual_plugin_path"
        actual_path.mkdir()
        
        with (
            patch("cpex.tools.catalog.subprocess.run"),
            patch("cpex.tools.catalog.find_package_path", return_value=source_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=actual_path),
            patch.object(catalog, "update_plugin_version_registry"),
        ):
            manifest, plugin_path = catalog.install_from_local(source_dir)
            
            # Should return the actual path from versions.json
            assert plugin_path == actual_path



class TestPluginCatalogInstallFromGit:
    """Tests for PluginCatalog.install_from_git method."""

    def test_install_from_git_success_https(self, tmp_path, mock_github_env):
        """Test successful installation from Git using HTTPS URL."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create mock extracted package with manifest
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        # Create a mock archive
        archive_path = tmp_path / "test_plugin-1.0.0.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(plugin_dir, arcname="test_plugin")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("cpex.tools.catalog.find_package_path", return_value=plugin_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=plugin_dir),
            patch.object(catalog, "update_plugin_version_registry"),
            patch("shutil.rmtree"),
        ):
            # Mock pip download to create the archive
            def mock_run(*args, **kwargs):
                if "download" in args[0]:
                    # Simulate pip download creating the archive
                    pass
                return Mock(returncode=0)
            
            mock_subprocess.side_effect = mock_run
            
            url = "test_plugin @ git+https://github.com/example/test_plugin.git"
            manifest, plugin_path = catalog.install_from_git(url)
            
            assert manifest.name == "test_plugin"
            assert manifest.kind == "native"
            assert plugin_path == plugin_dir
            # Should call subprocess twice: once for download, once for install
            assert mock_subprocess.call_count == 2

    def test_install_from_git_success_ssh(self, tmp_path, mock_github_env):
        """Test successful installation from Git using SSH URL."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        archive_path = tmp_path / "test_plugin-1.0.0.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(plugin_dir, arcname="test_plugin")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("cpex.tools.catalog.find_package_path", return_value=plugin_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=plugin_dir),
            patch.object(catalog, "update_plugin_version_registry"),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            # Use git@ format which is the standard SSH format
            url = "test_plugin @ git+git@github.com:example/test_plugin.git"
            manifest, plugin_path = catalog.install_from_git(url)
            
            assert manifest.name == "test_plugin"
            assert plugin_path == plugin_dir

    def test_install_from_git_with_branch(self, tmp_path, mock_github_env):
        """Test installation from Git with specific branch."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        archive_path = tmp_path / "test_plugin-1.0.0.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(plugin_dir, arcname="test_plugin")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("cpex.tools.catalog.find_package_path", return_value=plugin_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=plugin_dir),
            patch.object(catalog, "update_plugin_version_registry"),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            url = "test_plugin @ git+https://github.com/example/test_plugin.git@master"
            manifest, plugin_path = catalog.install_from_git(url)
            
            assert manifest.name == "test_plugin"
            # Verify that the branch was included in the pip install command
            install_call = [call for call in mock_subprocess.call_args_list if "install" in str(call)]
            assert len(install_call) > 0

    def test_install_from_git_isolated_venv(self, tmp_path, mock_github_env):
        """Test installation of isolated_venv plugin from Git."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "isolated_venv",
            "description": "Test isolated plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {"requirements_file": "requirements.txt"},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        # Create requirements file
        requirements_file = plugin_dir / "requirements.txt"
        requirements_file.write_text("pytest>=7.0.0\n")
        
        archive_path = tmp_path / "test_plugin-1.0.0.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(plugin_dir, arcname="test_plugin")
            tar.add(requirements_file, arcname="test_plugin/requirements.txt")
        
        venv_path = tmp_path / "venv_path"
        venv_path.mkdir()
        venv_bin = venv_path / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        venv_python = venv_bin / "python"
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch.object(catalog, "_initialize_isolated_venv", return_value=venv_path),
            patch.object(catalog, "_get_venv_python_executable", return_value=str(venv_python)),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=venv_path),
            patch.object(catalog, "update_plugin_version_registry"),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            url = "test_plugin @ git+https://github.com/example/test_plugin.git"
            manifest, plugin_path = catalog.install_from_git(url)
            
            assert manifest.kind == "isolated_venv"
            assert plugin_path == venv_path
            # Should call subprocess twice: download and install into isolated venv
            assert mock_subprocess.call_count == 2
            # Verify install was called with venv python (not download which also contains "install")
            install_calls = [call for call in mock_subprocess.call_args_list if "pip', 'install" in str(call)]
            assert len(install_calls) == 1
            assert str(venv_python) in str(install_calls[0])

    def test_install_from_git_invalid_url_format(self, mock_github_env):
        """Test error when URL format is invalid (missing @)."""
        catalog = PluginCatalog()
        
        with pytest.raises(ValueError) as exc_info:
            catalog.install_from_git("test_plugin")
        
        assert "Invalid Git URL format" in str(exc_info.value)
        assert "Expected format" in str(exc_info.value)

    def test_install_from_git_missing_git_prefix(self, mock_github_env):
        """Test error when git+ prefix is missing."""
        catalog = PluginCatalog()
        
        with pytest.raises(ValueError) as exc_info:
            catalog.install_from_git("test_plugin @ https://github.com/example/test_plugin.git")
        
        assert "Git URL must start with 'git+'" in str(exc_info.value)

    def test_install_from_git_invalid_git_url(self, mock_github_env):
        """Test error when Git URL is invalid."""
        catalog = PluginCatalog()
        
        with pytest.raises(ValueError) as exc_info:
            catalog.install_from_git("test_plugin @ git+invalid://not-a-valid-url")
        
        assert "Invalid Git repository URL" in str(exc_info.value)

    def test_install_from_git_download_failure(self, tmp_path, mock_github_env):
        """Test error when pip download fails."""
        catalog = PluginCatalog()
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.side_effect = subprocess.CalledProcessError(
                1, ["pip", "download"], stderr="Download failed"
            )
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog.install_from_git("test_plugin @ git+https://github.com/example/test_plugin.git")
            
            assert "Failed to install test_plugin from Git" in str(exc_info.value)

    def test_install_from_git_no_archive_found(self, tmp_path, mock_github_env):
        """Test error when no archive is found after download."""
        catalog = PluginCatalog()
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog.install_from_git("test_plugin @ git+https://github.com/example/test_plugin.git")
            
            assert "No package archive found" in str(exc_info.value)

    def test_install_from_git_manifest_not_found(self, tmp_path, mock_github_env):
        """Test error when manifest is not found in package."""
        catalog = PluginCatalog()
        
        # Create archive without manifest
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        archive_path = tmp_path / "test_plugin-1.0.0.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(plugin_dir, arcname="test_plugin")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            # The method wraps FileNotFoundError in RuntimeError
            with pytest.raises(RuntimeError) as exc_info:
                catalog.install_from_git("test_plugin @ git+https://github.com/example/test_plugin.git")
            
            assert "Unexpected error installing test_plugin from Git" in str(exc_info.value)
            assert "plugin-manifest.yaml not found" in str(exc_info.value)

    def test_install_from_git_install_failure(self, tmp_path, mock_github_env):
        """Test error when pip install fails."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        archive_path = tmp_path / "test_plugin-1.0.0.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(plugin_dir, arcname="test_plugin")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("shutil.rmtree"),
        ):
            # First call (download) succeeds, second call (install) fails
            mock_subprocess.side_effect = [
                Mock(returncode=0),  # download succeeds
                subprocess.CalledProcessError(1, ["pip", "install"], stderr="Install failed"),  # install fails
            ]
            
            with pytest.raises(RuntimeError) as exc_info:
                catalog.install_from_git("test_plugin @ git+https://github.com/example/test_plugin.git")
            
            assert "Failed to install test_plugin from Git" in str(exc_info.value)

    def test_install_from_git_cleanup_on_error(self, tmp_path, mock_github_env):
        """Test that temporary directory is cleaned up even on error."""
        catalog = PluginCatalog()
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("shutil.rmtree") as mock_rmtree,
        ):
            mock_subprocess.side_effect = subprocess.CalledProcessError(
                1, ["pip", "download"], stderr="Download failed"
            )
            
            with pytest.raises(RuntimeError):
                catalog.install_from_git("test_plugin @ git+https://github.com/example/test_plugin.git")
            
            # Verify cleanup was called
            mock_rmtree.assert_called_once()
            assert str(tmp_path) in str(mock_rmtree.call_args)

    def test_install_from_git_with_zip_archive(self, tmp_path, mock_github_env):
        """Test installation from Git with zip archive."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        # Create a zip archive
        archive_path = tmp_path / "test_plugin-1.0.0.zip"
        with zipfile.ZipFile(archive_path, "w") as zipf:
            zipf.write(manifest_file, arcname="test_plugin/plugin-manifest.yaml")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("cpex.tools.catalog.find_package_path", return_value=plugin_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=plugin_dir),
            patch.object(catalog, "update_plugin_version_registry"),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            url = "test_plugin @ git+https://github.com/example/test_plugin.git"
            manifest, plugin_path = catalog.install_from_git(url)
            
            assert manifest.name == "test_plugin"

    def test_install_from_git_with_wheel(self, tmp_path, mock_github_env):
        """Test installation from Git with wheel archive."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        plugin_dir = extract_dir / "test_plugin"
        plugin_dir.mkdir()
        
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "kind": "native",
            "description": "Test plugin",
            "author": "Test Author",
            "tags": ["test"],
            "available_hooks": ["tools"],
            "default_config": {},
        }
        manifest_file = plugin_dir / "plugin-manifest.yaml"
        manifest_file.write_text(yaml.safe_dump(manifest_data))
        
        # Create a wheel archive (which is a zip file)
        archive_path = tmp_path / "test_plugin-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(archive_path, "w") as zipf:
            zipf.write(manifest_file, arcname="test_plugin/plugin-manifest.yaml")
        
        with (
            patch("cpex.tools.catalog.subprocess.run") as mock_subprocess,
            patch("cpex.tools.catalog.tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("cpex.tools.catalog.find_package_path", return_value=plugin_dir),
            patch.object(catalog, "_persist_manifest"),
            patch.object(catalog, "_find_and_load_versions_json", return_value=plugin_dir),
            patch.object(catalog, "update_plugin_version_registry"),
            patch("shutil.rmtree"),
        ):
            mock_subprocess.return_value = Mock(returncode=0)
            
            url = "test_plugin @ git+https://github.com/example/test_plugin.git"
            manifest, plugin_path = catalog.install_from_git(url)
            
            assert manifest.name == "test_plugin"


# ---------------------------------------------------------------------------
# _extract_package_archive — path traversal guards
# ---------------------------------------------------------------------------

class TestExtractPackageArchivePathTraversal:
    """Verify that _extract_package_archive rejects archives with unsafe member paths."""

    @pytest.fixture()
    def catalog(self):
        with patch("cpex.tools.catalog.PluginCatalog.__init__", return_value=None):
            c = PluginCatalog.__new__(PluginCatalog)
            c.python_executable = sys.executable
            return c

    # --- tar.gz -----------------------------------------------------------

    def test_tar_traversal_rejected(self, catalog, tmp_path):
        """A tar member whose path escapes extract_dir raises and writes nothing."""
        import io
        archive = tmp_path / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            data = b"pwned"
            info = tarfile.TarInfo(name="../evil.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(Exception):
            catalog._extract_package_archive(archive, extract_dir)

        assert not (tmp_path / "evil.txt").exists()

    def test_tar_benign_succeeds(self, catalog, tmp_path):
        """A well-formed tar.gz extracts correctly."""
        import io
        archive = tmp_path / "good.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            data = b"hello"
            info = tarfile.TarInfo(name="subdir/hello.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        catalog._extract_package_archive(archive, extract_dir)

        assert (extract_dir / "subdir" / "hello.txt").read_bytes() == b"hello"

    # --- zip / .whl -------------------------------------------------------

    def test_zip_traversal_rejected(self, catalog, tmp_path):
        """A zip member whose path escapes extract_dir raises and writes nothing."""
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../evil.txt", "pwned")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(RuntimeError, match="Unsafe path"):
            catalog._extract_package_archive(archive, extract_dir)

        assert not (tmp_path / "evil.txt").exists()

    def test_whl_traversal_rejected(self, catalog, tmp_path):
        """A .whl (zip) member whose path escapes extract_dir raises and writes nothing."""
        archive = tmp_path / "evil-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../evil.txt", "pwned")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(RuntimeError, match="Unsafe path"):
            catalog._extract_package_archive(archive, extract_dir)

        assert not (tmp_path / "evil.txt").exists()

    def test_zip_absolute_path_rejected(self, catalog, tmp_path):
        """A zip member with an absolute path raises before any extraction."""
        archive = tmp_path / "absolute.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("/etc/passwd", "root:x:0:0")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(RuntimeError, match="Unsafe path"):
            catalog._extract_package_archive(archive, extract_dir)

    def test_zip_benign_succeeds(self, catalog, tmp_path):
        """A well-formed zip extracts correctly."""
        archive = tmp_path / "good.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("pkg/hello.txt", "world")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        catalog._extract_package_archive(archive, extract_dir)

        assert (extract_dir / "pkg" / "hello.txt").read_text() == "world"

class TestPluginCatalogUpdatePluginVersionRegistry:
    """Tests for PluginCatalog.update_plugin_version_registry method."""

    def test_update_plugin_version_registry_creates_new_file(self, tmp_path, mock_github_env):
        """Test creating a new versions.json file when none exists."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        manifest = create_test_manifest(name="test_plugin", version="1.0.0")
        relpath = Path("plugins/test_plugin")
        
        catalog.update_plugin_version_registry(manifest, relpath)
        
        # Verify file was created
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        assert versions_file.exists()
        
        # Verify content
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 1
        assert data["versions"][0]["version"] == "1.0.0"
        assert data["versions"][0]["manifest_file"] == str(relpath)
        assert data["latest"]["version"] == "1.0.0"

    def test_update_plugin_version_registry_adds_new_version(self, tmp_path, mock_github_env):
        """Test adding a new version to existing registry."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create initial version
        manifest1 = create_test_manifest(name="test_plugin", version="1.0.0")
        relpath1 = Path("plugins/test_plugin")
        catalog.update_plugin_version_registry(manifest1, relpath1)
        
        # Add new version
        manifest2 = create_test_manifest(name="test_plugin", version="2.0.0")
        relpath2 = Path("plugins/test_plugin")
        catalog.update_plugin_version_registry(manifest2, relpath2)
        
        # Verify both versions exist
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 2
        versions = [v["version"] for v in data["versions"]]
        assert "1.0.0" in versions
        assert "2.0.0" in versions
        assert data["latest"]["version"] == "2.0.0"

    def test_update_plugin_version_registry_handles_duplicate_version(self, tmp_path, mock_github_env):
        """Test that duplicate versions are not added."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        manifest = create_test_manifest(name="test_plugin", version="1.0.0")
        relpath = Path("plugins/test_plugin")
        
        # Add same version twice
        catalog.update_plugin_version_registry(manifest, relpath)
        catalog.update_plugin_version_registry(manifest, relpath)
        
        # Verify only one version exists
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 1
        assert data["versions"][0]["version"] == "1.0.0"

    def test_update_plugin_version_registry_updates_latest_correctly(self, tmp_path, mock_github_env):
        """Test that latest version is updated correctly when adding versions out of order."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Add version 2.0.0 first
        manifest2 = create_test_manifest(name="test_plugin", version="2.0.0")
        catalog.update_plugin_version_registry(manifest2, Path("plugins/test_plugin"))
        
        # Add version 1.0.0
        manifest1 = create_test_manifest(name="test_plugin", version="1.0.0")
        catalog.update_plugin_version_registry(manifest1, Path("plugins/test_plugin"))
        
        # Add version 3.0.0
        manifest3 = create_test_manifest(name="test_plugin", version="3.0.0")
        catalog.update_plugin_version_registry(manifest3, Path("plugins/test_plugin"))
        
        # Verify latest is 3.0.0
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert data["latest"]["version"] == "3.0.0"
        assert len(data["versions"]) == 3

    def test_update_plugin_version_registry_with_prerelease_versions(self, tmp_path, mock_github_env):
        """Test handling of pre-release versions."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Add stable version
        manifest1 = create_test_manifest(name="test_plugin", version="1.0.0")
        catalog.update_plugin_version_registry(manifest1, Path("plugins/test_plugin"))
        
        # Add pre-release version
        manifest2 = create_test_manifest(name="test_plugin", version="2.0.0rc1")
        catalog.update_plugin_version_registry(manifest2, Path("plugins/test_plugin"))
        
        # Verify latest is the rc version (higher version number)
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 2
        assert data["latest"]["version"] == "2.0.0rc1"

    def test_update_plugin_version_registry_with_dev_versions(self, tmp_path, mock_github_env):
        """Test handling of development versions."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Add dev version
        manifest1 = create_test_manifest(name="test_plugin", version="1.0.0.dev1")
        catalog.update_plugin_version_registry(manifest1, Path("plugins/test_plugin"))
        
        # Add stable version
        manifest2 = create_test_manifest(name="test_plugin", version="1.0.0")
        catalog.update_plugin_version_registry(manifest2, Path("plugins/test_plugin"))
        
        # Verify latest is stable version
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 2
        assert data["latest"]["version"] == "1.0.0"

    def test_update_plugin_version_registry_preserves_existing_data(self, tmp_path, mock_github_env):
        """Test that existing version data is preserved when adding new versions."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Manually create a versions.json with additional metadata
        versions_dir = tmp_path / "catalog" / "test_plugin"
        versions_dir.mkdir(parents=True)
        versions_file = versions_dir / "versions.json"
        
        initial_data = {
            "latest": {
                "version": "1.0.0",
                "released": "2024-01-01T00:00:00Z",
                "manifest_file": "plugins/test_plugin",
                "deprecated": False,
                "breaking_changes": False,
                "changelog": "Initial release"
            },
            "versions": [
                {
                    "version": "1.0.0",
                    "released": "2024-01-01T00:00:00Z",
                    "manifest_file": "plugins/test_plugin",
                    "deprecated": False,
                    "breaking_changes": False,
                    "changelog": "Initial release"
                }
            ]
        }
        versions_file.write_text(json.dumps(initial_data, indent=2))
        
        # Add new version
        manifest2 = create_test_manifest(name="test_plugin", version="2.0.0")
        catalog.update_plugin_version_registry(manifest2, Path("plugins/test_plugin"))
        
        # Verify old version data is preserved
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 2
        old_version = next(v for v in data["versions"] if v["version"] == "1.0.0")
        assert old_version["changelog"] == "Initial release"
        assert old_version["released"] == "2024-01-01T00:00:00Z"

    def test_update_plugin_version_registry_with_complex_version_ordering(self, tmp_path, mock_github_env):
        """Test version ordering with complex version strings."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Add versions in random order
        versions = ["1.0.0", "2.0.0rc1", "1.5.0", "2.0.0", "1.0.1", "2.1.0a1"]
        for version in versions:
            manifest = create_test_manifest(name="test_plugin", version=version)
            catalog.update_plugin_version_registry(manifest, Path("plugins/test_plugin"))
        
        # Verify latest is 2.1.0a1 (highest version)
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert len(data["versions"]) == 6
        assert data["latest"]["version"] == "2.1.0a1"

    def test_update_plugin_version_registry_creates_parent_directories(self, tmp_path, mock_github_env):
        """Test that parent directories are created if they don't exist."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Don't create the directory beforehand
        manifest = create_test_manifest(name="test_plugin", version="1.0.0")
        catalog.update_plugin_version_registry(manifest, Path("plugins/test_plugin"))
        
        # Verify directory and file were created
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        assert versions_file.exists()
        assert versions_file.parent.exists()

    def test_update_plugin_version_registry_with_invalid_existing_json(self, tmp_path, mock_github_env):
        """Test handling of corrupted existing versions.json file."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Create corrupted versions.json
        versions_dir = tmp_path / "catalog" / "test_plugin"
        versions_dir.mkdir(parents=True)
        versions_file = versions_dir / "versions.json"
        versions_file.write_text("invalid json content")
        
        # Attempt to update should raise an error
        manifest = create_test_manifest(name="test_plugin", version="1.0.0")
        with pytest.raises(json.JSONDecodeError):
            catalog.update_plugin_version_registry(manifest, Path("plugins/test_plugin"))

    def test_update_plugin_version_registry_timestamp_format(self, tmp_path, mock_github_env):
        """Test that timestamp is in correct ISO format with Z suffix."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        manifest = create_test_manifest(name="test_plugin", version="1.0.0")
        catalog.update_plugin_version_registry(manifest, Path("plugins/test_plugin"))
        
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        released = data["versions"][0]["released"]
        # Verify format: ends with Z and contains T
        assert released.endswith("Z")
        assert "T" in released
        # Verify it's a valid ISO format
        from datetime import datetime
        datetime.fromisoformat(released.replace("Z", "+00:00"))

    def test_update_plugin_version_registry_with_epoch_versions(self, tmp_path, mock_github_env):
        """Test handling of versions with epochs."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        # Add version with epoch
        manifest1 = create_test_manifest(name="test_plugin", version="1!1.0.0")
        catalog.update_plugin_version_registry(manifest1, Path("plugins/test_plugin"))
        
        # Add version without epoch (should be lower)
        manifest2 = create_test_manifest(name="test_plugin", version="2.0.0")
        catalog.update_plugin_version_registry(manifest2, Path("plugins/test_plugin"))
        
        # Verify epoch version is latest
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        
        assert data["latest"]["version"] == "1!1.0.0"

    def test_update_plugin_version_registry_relpath_stored_correctly(self, tmp_path, mock_github_env):
        """Test that relative path is stored correctly in manifest_file."""
        catalog = PluginCatalog()
        catalog.catalog_folder = str(tmp_path / "catalog")
        
        manifest = create_test_manifest(name="test_plugin", version="1.0.0")
        relpath = Path("custom/path/to/plugin")
        
        catalog.update_plugin_version_registry(manifest, relpath)
        
        versions_file = tmp_path / "catalog" / "test_plugin" / "versions.json"
        with versions_file.open("r") as f:
            data = json.load(f)
        


class TestPluginCatalogVerMethod:
    """Tests for PluginCatalog._ver method."""

    def test_ver_valid_simple_version(self, mock_github_env):
        """Test parsing a simple valid version string."""
        catalog = PluginCatalog()
        version = catalog._ver("1.0.0")
        assert str(version) == "1.0.0"

    def test_ver_valid_complex_version(self, mock_github_env):
        """Test parsing a complex valid version string."""
        catalog = PluginCatalog()
        version = catalog._ver("1.2.3")
        assert str(version) == "1.2.3"

    def test_ver_valid_version_with_epoch(self, mock_github_env):
        """Test parsing a version with epoch."""
        catalog = PluginCatalog()
        version = catalog._ver("1!2.0.0")
        assert str(version) == "1!2.0.0"

    def test_ver_valid_prerelease_version(self, mock_github_env):
        """Test parsing a pre-release version."""
        catalog = PluginCatalog()
        version = catalog._ver("1.0.0rc1")
        assert str(version) == "1.0.0rc1"

    def test_ver_valid_post_release_version(self, mock_github_env):
        """Test parsing a post-release version."""
        catalog = PluginCatalog()
        version = catalog._ver("1.0.0.post1")
        assert str(version) == "1.0.0.post1"

    def test_ver_valid_dev_version(self, mock_github_env):
        """Test parsing a development version."""
        catalog = PluginCatalog()
        version = catalog._ver("1.0.0.dev1")
        assert str(version) == "1.0.0.dev1"

    def test_ver_invalid_version_returns_zero(self, mock_github_env):
        """Test that invalid version strings return Version('0')."""
        catalog = PluginCatalog()
        version = catalog._ver("invalid.version")
        assert str(version) == "0"

    def test_ver_invalid_version_with_special_chars(self, mock_github_env):
        """Test that version with special characters returns Version('0')."""
        catalog = PluginCatalog()
        version = catalog._ver("1.0.0@beta")
        assert str(version) == "0"

    def test_ver_empty_string_returns_zero(self, mock_github_env):
        """Test that empty string returns Version('0')."""
        catalog = PluginCatalog()
        version = catalog._ver("")
        assert str(version) == "0"

    def test_ver_invalid_semantic_version(self, mock_github_env):
        """Test that version with 'v' prefix is actually valid (packaging strips it)."""
        catalog = PluginCatalog()
        version = catalog._ver("v1.0")
        # packaging.version.Version actually accepts and strips 'v' prefix
        assert str(version) == "1.0"

    def test_ver_version_with_local_identifier(self, mock_github_env):
        """Test parsing a version with local identifier."""
        catalog = PluginCatalog()
        version = catalog._ver("1.0.0+local.build")
        assert str(version) == "1.0.0+local.build"

    def test_ver_logs_debug_on_invalid_version(self, mock_github_env, caplog):
        """Test that debug log is created for invalid versions."""
        import logging
        catalog = PluginCatalog()
        
        with caplog.at_level(logging.DEBUG):
            catalog._ver("not-a-version")
        
        assert "Could not parse version" in caplog.text
        assert "treating as lowest" in caplog.text

    def test_ver_whitespace_version(self, mock_github_env):
        """Test that whitespace-only version returns Version('0')."""
        catalog = PluginCatalog()
        version = catalog._ver("   ")
        assert str(version) == "0"

    def test_ver_version_with_v_prefix(self, mock_github_env):
        """Test that version with 'v' prefix is valid (packaging strips it)."""
        catalog = PluginCatalog()
        version = catalog._ver("v1.0.0")
        # packaging.version.Version actually accepts and strips 'v' prefix
        assert str(version) == "1.0.0"

    def test_ver_numeric_only_version(self, mock_github_env):
        """Test parsing a single numeric version."""
        catalog = PluginCatalog()
        version = catalog._ver("1")
        assert str(version) == "1"

    def test_ver_comparison_works_correctly(self, mock_github_env):
        """Test that version comparison works as expected."""
        catalog = PluginCatalog()
        v1 = catalog._ver("1.0.0")
        v2 = catalog._ver("2.0.0")
        v_invalid = catalog._ver("invalid")
        
        assert v1 < v2
        assert v_invalid < v1
        assert v_invalid == catalog._ver("0")

    def test_ver_prerelease_comparison(self, mock_github_env):
        """Test that pre-release versions compare correctly."""
        catalog = PluginCatalog()
        v_stable = catalog._ver("1.0.0")
        v_rc = catalog._ver("1.0.0rc1")
        v_dev = catalog._ver("1.0.0.dev1")
        
        assert v_dev < v_rc < v_stable

    def test_ver_epoch_comparison(self, mock_github_env):
        """Test that epoch versions compare correctly."""
        catalog = PluginCatalog()
        v_no_epoch = catalog._ver("2.0.0")
        v_with_epoch = catalog._ver("1!1.0.0")
        
        # Epoch takes precedence
        assert v_with_epoch > v_no_epoch
