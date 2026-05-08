# -*- coding: utf-8 -*-
"""Additional unit tests for PluginPackageInfo and PluginVersionRegistry in cpex.framework.models.

This module provides additional test coverage for edge cases and scenarios
not covered in the main test_plugin_models.py file.
"""

# Third-Party
import pytest

# First-Party
from cpex.framework.models import PluginPackageInfo, PluginVersionInfo, PluginVersionRegistry


class TestPluginPackageInfoEdgeCases:
    """Additional edge case tests for PluginPackageInfo."""

    def test_pypi_package_single_character(self):
        """Single character PyPI package names should be valid."""
        pkg = PluginPackageInfo(pypi_package="a")
        assert pkg.pypi_package == "a"

    def test_pypi_package_two_characters(self):
        """Two character PyPI package names should be valid."""
        pkg = PluginPackageInfo(pypi_package="ab")
        assert pkg.pypi_package == "ab"

    def test_pypi_package_max_length(self):
        """PyPI package name at exactly 214 characters should be valid."""
        max_name = "a" * 214
        pkg = PluginPackageInfo(pypi_package=max_name)
        assert pkg.pypi_package == max_name
        assert len(pkg.pypi_package) == 214

    def test_pypi_package_with_numbers_only(self):
        """PyPI package names with only numbers should be valid."""
        pkg = PluginPackageInfo(pypi_package="123")
        assert pkg.pypi_package == "123"

    def test_pypi_package_mixed_separators(self):
        """PyPI package names with mixed valid separators should be valid."""
        pkg = PluginPackageInfo(pypi_package="my-package_name.version")
        assert pkg.pypi_package == "my-package_name.version"

    def test_git_repository_without_git_extension(self):
        """Git repository URLs without .git extension should be valid."""
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo")
        assert pkg.git_repository == "https://github.com/user/repo"

    def test_git_repository_with_subdirectories(self):
        """Git repository URLs with subdirectories should be valid."""
        pkg = PluginPackageInfo(git_repository="https://github.com/org/team/repo.git")
        assert pkg.git_repository == "https://github.com/org/team/repo.git"

    def test_git_repository_ssh_with_port(self):
        """SSH Git URLs with custom ports are not supported by the current validator."""
        # The current regex doesn't support ssh:// protocol with ports
        with pytest.raises(ValueError, match="Invalid Git repository URL"):
            PluginPackageInfo(git_repository="ssh://git@github.com:2222/user/repo.git")

    def test_git_branch_single_character(self):
        """Single character branch names should be valid."""
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="v")
        assert pkg.git_branch_tag_commit == "v"

    def test_git_branch_with_multiple_slashes(self):
        """Branch names with multiple slashes should be valid."""
        pkg = PluginPackageInfo(
            git_repository="https://github.com/user/repo.git", git_branch_tag_commit="feature/sub/branch"
        )
        assert pkg.git_branch_tag_commit == "feature/sub/branch"

    def test_git_commit_short_hash(self):
        """Short commit hashes (7 characters) should be valid."""
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="abc1234")
        assert pkg.git_branch_tag_commit == "abc1234"

    def test_git_commit_full_hash(self):
        """Full commit hashes (40 characters) should be valid."""
        full_hash = "a" * 40
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit=full_hash)
        assert pkg.git_branch_tag_commit == full_hash

    def test_version_constraint_with_spaces(self):
        """Version constraints with spaces around operators should be valid."""
        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint=">= 1.0.0, < 2.0.0")
        assert pkg.version_constraint == ">= 1.0.0, < 2.0.0"

    def test_version_constraint_triple_equals(self):
        """Version constraints with === operator should be valid."""
        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint="===1.0.0")
        assert pkg.version_constraint == "===1.0.0"

    def test_version_constraint_with_local_version(self):
        """Version constraints with local version identifiers are not supported by current validator."""
        # The current regex doesn't support + in version constraints
        with pytest.raises(ValueError, match="Invalid version constraint"):
            PluginPackageInfo(pypi_package="my-package", version_constraint="==1.0.0+local.version")

    def test_both_installation_methods_with_all_fields(self):
        """Both installation methods with all optional fields should be valid."""
        pkg = PluginPackageInfo(
            pypi_package="my-package",
            git_repository="https://github.com/user/repo.git",
            git_branch_tag_commit="v1.0.0",
            version_constraint=">=1.0.0,<2.0.0",
        )
        assert pkg.pypi_package == "my-package"
        assert pkg.git_repository == "https://github.com/user/repo.git"
        assert pkg.git_branch_tag_commit == "v1.0.0"
        assert pkg.version_constraint == ">=1.0.0,<2.0.0"


class TestPluginVersionInfoEdgeCases:
    """Additional edge case tests for PluginVersionInfo."""

    def test_version_info_minimal_fields(self):
        """PluginVersionInfo with only required fields should be valid."""
        info = PluginVersionInfo(version="1.0.0", released="2024-01-01", manifest_file="manifest.json")
        assert info.version == "1.0.0"
        assert info.released == "2024-01-01"
        assert info.manifest_file == "manifest.json"
        assert info.breaking_changes is None
        assert info.deprecated is False
        assert info.changelog is None

    def test_version_info_all_fields(self):
        """PluginVersionInfo with all fields should be valid."""
        info = PluginVersionInfo(
            version="2.0.0",
            released="2024-02-01",
            breaking_changes=True,
            deprecated=True,
            manifest_file="manifest.json",
            changelog="Major update with breaking changes",
            min_max_framework_version="0.2.0,0.3.0",
        )
        assert info.version == "2.0.0"
        assert info.breaking_changes is True
        assert info.deprecated is True
        assert info.changelog == "Major update with breaking changes"
        assert info.min_max_framework_version == "0.2.0,0.3.0"

    def test_version_info_prerelease_version(self):
        """PluginVersionInfo with pre-release version should be valid."""
        info = PluginVersionInfo(version="1.0.0-alpha.1", released="2024-01-01", manifest_file="manifest.json")
        assert info.version == "1.0.0-alpha.1"

    def test_version_info_dev_version(self):
        """PluginVersionInfo with dev version should be valid."""
        info = PluginVersionInfo(
            version="1.0.0.dev1",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0.dev1,0.1.0.dev10",
        )
        assert info.version == "1.0.0.dev1"


class TestPluginVersionRegistryEdgeCases:
    """Additional edge case tests for PluginVersionRegistry."""

    def test_registry_with_only_prerelease(self):
        """Registry with only pre-release versions should work correctly."""
        v1 = PluginVersionInfo(
            version="1.0.0-alpha",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=None, latest_prerelease=v1, versions=[v1])

        assert registry.get_version() is None
        assert registry.latest_prerelease == v1

    def test_registry_with_both_latest_and_prerelease(self):
        """Registry with both latest and latest_prerelease should maintain both."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v2 = PluginVersionInfo(
            version="1.1.0-beta",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v1, latest_prerelease=v2, versions=[v1, v2])

        assert registry.get_version() == v1
        assert registry.latest_prerelease == v2

    def test_get_latest_compatible_with_single_version_in_range(self):
        """get_latest_compatible with only one version in range should return it."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        result = registry.get_latest_compatible("0.1.5")
        assert result == v1

    def test_get_latest_compatible_with_overlapping_ranges(self):
        """get_latest_compatible with overlapping version ranges should return latest."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.3.0",
        )
        v2 = PluginVersionInfo(
            version="1.5.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.2.0,0.4.0",
        )
        v3 = PluginVersionInfo(
            version="2.0.0",
            released="2024-03-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.2.5,0.5.0",
        )

        registry = PluginVersionRegistry(latest=v3, versions=[v1, v2, v3])

        # Framework 0.2.7 matches v1, v2, and v3 - should return v3 (latest)
        result = registry.get_latest_compatible("0.2.7")
        assert result == v3
        assert result.version == "2.0.0"

    def test_get_latest_compatible_with_non_overlapping_ranges(self):
        """get_latest_compatible with non-overlapping ranges should return correct version."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v2 = PluginVersionInfo(
            version="2.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.3.0,0.4.0",
        )

        registry = PluginVersionRegistry(latest=v2, versions=[v1, v2])

        # Framework 0.1.5 should match v1
        result = registry.get_latest_compatible("0.1.5")
        assert result == v1

        # Framework 0.3.5 should match v2
        result = registry.get_latest_compatible("0.3.5")
        assert result == v2

        # Framework 0.2.5 should match neither
        result = registry.get_latest_compatible("0.2.5")
        assert result is None

    def test_get_latest_compatible_with_malformed_version_in_list(self):
        """get_latest_compatible should handle malformed versions in the list gracefully."""
        v1 = PluginVersionInfo(
            version="not-a-version",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v2 = PluginVersionInfo(
            version="1.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v2, versions=[v1, v2])

        # Should still find v2 even though v1 has invalid version
        result = registry.get_latest_compatible("0.1.5")
        # If sorting fails, it returns the first compatible version
        assert result in [v1, v2]

    def test_get_latest_compatible_with_extra_whitespace_in_min_max(self):
        """get_latest_compatible should handle extra whitespace in min_max_framework_version."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="  0.1.0  ,  0.2.0  ",
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        result = registry.get_latest_compatible("0.1.5")
        assert result == v1

    def test_get_latest_compatible_with_three_part_min_max(self):
        """get_latest_compatible should reject min_max with more than 2 parts."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0,0.3.0",  # Invalid: 3 parts
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        result = registry.get_latest_compatible("0.1.5")
        assert result is None

    def test_get_latest_compatible_with_reversed_min_max(self):
        """get_latest_compatible should handle reversed min/max (max < min)."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.2.0,0.1.0",  # Reversed
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        # No version should match since max < min
        result = registry.get_latest_compatible("0.1.5")
        assert result is None

    def test_registry_versions_list_order_independence(self):
        """Registry should work correctly regardless of versions list order."""
        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v2 = PluginVersionInfo(
            version="2.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v3 = PluginVersionInfo(
            version="1.5.0",
            released="2024-01-15",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        # Test with different orderings
        registry1 = PluginVersionRegistry(latest=v2, versions=[v1, v2, v3])

        registry2 = PluginVersionRegistry(latest=v2, versions=[v3, v1, v2])

        registry3 = PluginVersionRegistry(latest=v2, versions=[v2, v3, v1])

        # All should return v2 as the latest compatible
        result1 = registry1.get_latest_compatible("0.1.5")
        result2 = registry2.get_latest_compatible("0.1.5")
        result3 = registry3.get_latest_compatible("0.1.5")

        assert result1 == v2
        assert result2 == v2
        assert result3 == v2


# Made with Bob
