# -*- coding: utf-8 -*-
"""Tests for cpex.framework.models."""

# Standard
import os
from pathlib import Path

# Third-Party
import pytest

# First-Party
from cpex.framework.constants import EXTERNAL_PLUGIN_TYPE
from cpex.framework.models import (
    MCPClientConfig,
    MCPClientTLSConfig,
    MCPServerConfig,
    MCPServerTLSConfig,
    PluginConfig,
    TransportType,
)


def _write_file(tmp_path: Path, name: str) -> str:
    file_path = tmp_path / name
    file_path.write_text("data")
    return str(file_path)


def test_bool_parsing_via_settings(monkeypatch):
    """Bool fields on PluginsSettings handle true/false strings correctly."""
    # First-Party
    from cpex.framework.settings import PluginsSettings

    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_VERIFY", "true")
    assert PluginsSettings().client_mtls_verify is True

    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_VERIFY", "0")
    assert PluginsSettings().client_mtls_verify is False


def test_client_tls_from_env(monkeypatch, tmp_path):
    cert = _write_file(tmp_path, "client-cert.pem")
    key = _write_file(tmp_path, "client-key.pem")
    ca = _write_file(tmp_path, "client-ca.pem")

    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_CERTFILE", cert)
    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_KEYFILE", key)
    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_CA_BUNDLE", ca)
    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_KEYFILE_PASSWORD", "pw")
    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_VERIFY", "false")
    monkeypatch.setenv("PLUGINS_CLIENT_MTLS_CHECK_HOSTNAME", "0")

    config = MCPClientTLSConfig.from_env()
    assert config is not None
    assert config.certfile == os.path.expanduser(cert)
    assert config.keyfile == os.path.expanduser(key)
    assert config.ca_bundle == os.path.expanduser(ca)
    assert config.verify is False
    assert config.check_hostname is False


def test_server_tls_from_env_invalid_cert_reqs(monkeypatch):
    monkeypatch.setenv("PLUGINS_SERVER_SSL_CERT_REQS", "not-an-int")
    with pytest.raises(ValueError):
        MCPServerTLSConfig.from_env()


@pytest.mark.parametrize("uds_value", [""])
def test_server_config_uds_validation_errors(uds_value):
    with pytest.raises(ValueError):
        MCPServerConfig(uds=uds_value)


def test_server_config_uds_missing_parent(tmp_path):
    missing = tmp_path / "missing" / "sock"
    with pytest.raises(ValueError):
        MCPServerConfig(uds=str(missing))


def test_server_config_uds_valid(tmp_path):
    uds_path = tmp_path / "socket.sock"
    config = MCPServerConfig(uds=str(uds_path))
    assert config.uds == str(uds_path.resolve())


def test_server_config_tls_with_uds_raises(tmp_path):
    uds_path = tmp_path / "socket.sock"
    tls = MCPServerTLSConfig()
    with pytest.raises(ValueError):
        MCPServerConfig(uds=str(uds_path), tls=tls)


def test_server_config_from_env_invalid_port(monkeypatch):
    monkeypatch.setenv("PLUGINS_SERVER_PORT", "bad")
    with pytest.raises(ValueError):
        MCPServerConfig.from_env()


def test_server_config_from_env_with_tls(monkeypatch, tmp_path):
    cert = _write_file(tmp_path, "server-cert.pem")
    key = _write_file(tmp_path, "server-key.pem")
    monkeypatch.setenv("PLUGINS_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("PLUGINS_SERVER_PORT", "9000")
    monkeypatch.setenv("PLUGINS_SERVER_SSL_ENABLED", "true")
    monkeypatch.setenv("PLUGINS_SERVER_SSL_CERTFILE", cert)
    monkeypatch.setenv("PLUGINS_SERVER_SSL_KEYFILE", key)

    config = MCPServerConfig.from_env()
    assert config is not None
    assert config.host == "0.0.0.0"
    assert config.port == 9000
    assert config.tls is not None


def test_client_config_script_requires_executable(tmp_path):
    script = tmp_path / "script.txt"
    script.write_text("data")
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STDIO, script=str(script))


@pytest.mark.parametrize("cmd_value", [[], [""], [" ", "x"]])
def test_client_config_cmd_validation(cmd_value):
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STDIO, cmd=cmd_value)


@pytest.mark.parametrize("env_value", [{}, {"KEY": 1}])
def test_client_config_env_validation(env_value):
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STDIO, cmd=["python"], env=env_value)


def test_client_config_cwd_validation(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STDIO, cmd=["python"], cwd=str(missing))


@pytest.mark.parametrize("uds_value", [""])
def test_client_config_uds_validation_errors(uds_value):
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STREAMABLEHTTP, uds=uds_value)


def test_client_config_uds_missing_parent(tmp_path):
    missing = tmp_path / "missing" / "sock"
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STREAMABLEHTTP, uds=str(missing))


def test_client_config_tls_usage_errors(tmp_path):
    tls = MCPClientTLSConfig()
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STDIO, cmd=["python"], tls=tls)

    uds_path = tmp_path / "socket.sock"
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STREAMABLEHTTP, uds=str(uds_path), tls=tls)


def test_client_config_transport_field_errors():
    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.STDIO, url="https://example.com", cmd=["python"])

    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.SSE, script="script.py")

    with pytest.raises(ValueError):
        MCPClientConfig(proto=TransportType.SSE, uds="/tmp/socket.sock")


def test_plugin_config_stdio_requires_script_or_cmd():
    mcp = MCPClientConfig(proto=TransportType.STDIO, cmd=None)
    with pytest.raises(ValueError):
        PluginConfig(name="plug", kind="internal", mcp=mcp)


def test_plugin_config_stdio_script_and_cmd_conflict():
    mcp = MCPClientConfig(proto=TransportType.STDIO, script="script.py", cmd=["python"])
    with pytest.raises(ValueError):
        PluginConfig(name="plug", kind="internal", mcp=mcp)


def test_plugin_config_http_requires_url():
    mcp = MCPClientConfig(proto=TransportType.SSE)
    with pytest.raises(ValueError):
        PluginConfig(name="plug", kind="internal", mcp=mcp)


def test_plugin_config_external_requires_mcp():
    with pytest.raises(ValueError):
        PluginConfig(name="external", kind=EXTERNAL_PLUGIN_TYPE)


def test_plugin_config_external_config_disallowed():
    mcp = MCPClientConfig(proto=TransportType.SSE, url="https://example.com")
    with pytest.raises(ValueError):
        PluginConfig(name="external", kind=EXTERNAL_PLUGIN_TYPE, config={"x": 1}, mcp=mcp)


# =============================================================================
# PluginPackageInfo Validator Tests
# =============================================================================


class TestPluginPackageInfoValidators:
    """Tests for PluginPackageInfo field validators."""

    # -------------------------------------------------------------------------
    # PyPI Package Validator Tests
    # -------------------------------------------------------------------------

    def test_pypi_package_valid(self):
        """Valid PyPI package names should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        # Standard package names
        pkg = PluginPackageInfo(pypi_package="my-package")
        assert pkg.pypi_package == "my-package"

        pkg = PluginPackageInfo(pypi_package="my_package")
        assert pkg.pypi_package == "my_package"

        pkg = PluginPackageInfo(pypi_package="my.package")
        assert pkg.pypi_package == "my.package"

        pkg = PluginPackageInfo(pypi_package="MyPackage123")
        assert pkg.pypi_package == "MyPackage123"

        # Complex valid names
        pkg = PluginPackageInfo(pypi_package="apex-pii-filter")
        assert pkg.pypi_package == "apex-pii-filter"

        pkg = PluginPackageInfo(pypi_package="package_name.with-everything123")
        assert pkg.pypi_package == "package_name.with-everything123"

    def test_pypi_package_invalid_empty(self):
        """Empty or whitespace-only PyPI package names should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        # Empty string is treated as None, so model validator catches it
        with pytest.raises(ValueError, match="At least one installation method"):
            PluginPackageInfo(pypi_package="")

        with pytest.raises(ValueError, match="cannot be empty or whitespace"):
            PluginPackageInfo(pypi_package="   ")

    def test_pypi_package_invalid_start_end(self):
        """PyPI package names starting/ending with invalid characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package="-invalid")

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package="invalid-")

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package=".invalid")

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package="invalid.")

    def test_pypi_package_invalid_characters(self):
        """PyPI package names with invalid characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package="my package")

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package="my@package")

        with pytest.raises(ValueError, match="Invalid PyPI package name"):
            PluginPackageInfo(pypi_package="my/package")

    def test_pypi_package_too_long(self):
        """PyPI package names exceeding 214 characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        long_name = "a" * 215
        with pytest.raises(ValueError, match="exceeds maximum length of 214 characters"):
            PluginPackageInfo(pypi_package=long_name)

    def test_pypi_package_none_allowed(self):
        """None should be allowed for pypi_package when git_repository is provided."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git")
        assert pkg.pypi_package is None

    # -------------------------------------------------------------------------
    # Git Repository Validator Tests
    # -------------------------------------------------------------------------

    def test_git_repository_valid_https(self):
        """Valid HTTPS Git repository URLs should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git")
        assert pkg.git_repository == "https://github.com/user/repo.git"

        pkg = PluginPackageInfo(git_repository="https://gitlab.com/user/repo.git")
        assert pkg.git_repository == "https://gitlab.com/user/repo.git"

        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo")
        assert pkg.git_repository == "https://github.com/user/repo"

    def test_git_repository_valid_http(self):
        """Valid HTTP Git repository URLs should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="http://example.com/user/repo.git")
        assert pkg.git_repository == "http://example.com/user/repo.git"

    def test_git_repository_valid_git_protocol(self):
        """Valid git:// protocol URLs should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="git://github.com/user/repo.git")
        assert pkg.git_repository == "git://github.com/user/repo.git"

    def test_git_repository_valid_ssh(self):
        """Valid SSH Git repository URLs should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="git@github.com:user/repo.git")
        assert pkg.git_repository == "git@github.com:user/repo.git"

    def test_git_repository_invalid_empty(self):
        """Empty or whitespace-only Git repository URLs should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        # Empty string is treated as None, so model validator catches it
        with pytest.raises(ValueError, match="At least one installation method"):
            PluginPackageInfo(git_repository="")

        with pytest.raises(ValueError, match="cannot be empty or whitespace"):
            PluginPackageInfo(git_repository="   ")

    def test_git_repository_invalid_format(self):
        """Invalid Git repository URL formats should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="Invalid Git repository URL"):
            PluginPackageInfo(git_repository="not-a-valid-url")

        with pytest.raises(ValueError, match="Invalid Git repository URL"):
            PluginPackageInfo(git_repository="ftp://example.com/repo.git")

    def test_git_repository_none_allowed(self):
        """None should be allowed for git_repository when pypi_package is provided."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package")
        assert pkg.git_repository is None

    # -------------------------------------------------------------------------
    # Git Branch/Tag/Commit Validator Tests
    # -------------------------------------------------------------------------

    def test_git_branch_tag_commit_valid(self):
        """Valid Git branch/tag/commit references should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        # Branch names
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="main")
        assert pkg.git_branch_tag_commit == "main"

        pkg = PluginPackageInfo(
            git_repository="https://github.com/user/repo.git", git_branch_tag_commit="feature/new-feature"
        )
        assert pkg.git_branch_tag_commit == "feature/new-feature"

        # Tag names
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="v1.0.0")
        assert pkg.git_branch_tag_commit == "v1.0.0"

        # Commit hashes
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="abc123def456")
        assert pkg.git_branch_tag_commit == "abc123def456"

        pkg = PluginPackageInfo(
            git_repository="https://github.com/user/repo.git",
            git_branch_tag_commit="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        )
        assert pkg.git_branch_tag_commit == "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"

    def test_git_branch_tag_commit_invalid_empty(self):
        """Empty or whitespace-only Git references should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        # Empty string is treated as None, which is valid
        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="")
        assert pkg.git_branch_tag_commit is None

        with pytest.raises(ValueError, match="cannot be empty or whitespace"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="   ")

    def test_git_branch_tag_commit_invalid_characters(self):
        """Git references with invalid characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="Invalid Git branch/tag/commit"):
            PluginPackageInfo(
                git_repository="https://github.com/user/repo.git", git_branch_tag_commit="branch with spaces"
            )

        with pytest.raises(ValueError, match="Invalid Git branch/tag/commit"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="branch@invalid")

    def test_git_branch_tag_commit_invalid_start_end(self):
        """Git references with invalid start/end characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="Cannot start with"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="/invalid")

        with pytest.raises(ValueError, match="Cannot start with"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit=".invalid")

        with pytest.raises(ValueError, match="Cannot start with"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="-invalid")

        with pytest.raises(ValueError, match="end with"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="invalid/")

        with pytest.raises(ValueError, match="end with"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit="invalid.")

    def test_git_branch_tag_commit_too_long(self):
        """Git references exceeding 255 characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        long_ref = "a" * 256
        with pytest.raises(ValueError, match="exceeds maximum length of 255 characters"):
            PluginPackageInfo(git_repository="https://github.com/user/repo.git", git_branch_tag_commit=long_ref)

    def test_git_branch_tag_commit_none_allowed(self):
        """None should be allowed for git_branch_tag_commit."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git")
        assert pkg.git_branch_tag_commit is None

    # -------------------------------------------------------------------------
    # Version Constraint Validator Tests
    # -------------------------------------------------------------------------

    def test_version_constraint_valid_single(self):
        """Valid single version constraints should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint=">=1.0.0")
        assert pkg.version_constraint == ">=1.0.0"

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint="==1.2.3")
        assert pkg.version_constraint == "==1.2.3"

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint="~=1.2.3")
        assert pkg.version_constraint == "~=1.2.3"

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint="<2.0.0")
        assert pkg.version_constraint == "<2.0.0"

    def test_version_constraint_valid_multiple(self):
        """Valid multiple version constraints should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint=">=1.0.0,<2.0.0")
        assert pkg.version_constraint == ">=1.0.0,<2.0.0"

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint=">=1.0.0, <2.0.0, !=1.5.0")
        assert pkg.version_constraint == ">=1.0.0, <2.0.0, !=1.5.0"

    def test_version_constraint_valid_with_prerelease(self):
        """Version constraints with pre-release identifiers should be accepted."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint=">=1.0.0-alpha")
        assert pkg.version_constraint == ">=1.0.0-alpha"

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint="==1.0.0rc1")
        assert pkg.version_constraint == "==1.0.0rc1"

    def test_version_constraint_invalid_empty(self):
        """Empty or whitespace-only version constraints should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        # Empty string is treated as None, which is valid
        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint="")
        assert pkg.version_constraint is None

        with pytest.raises(ValueError, match="cannot be empty or whitespace"):
            PluginPackageInfo(pypi_package="my-package", version_constraint="   ")

    def test_version_constraint_invalid_format(self):
        """Invalid version constraint formats should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="Invalid version constraint"):
            PluginPackageInfo(pypi_package="my-package", version_constraint="invalid")

        with pytest.raises(ValueError, match="Invalid version constraint"):
            PluginPackageInfo(pypi_package="my-package", version_constraint="1.0.0")

    def test_version_constraint_invalid_empty_parts(self):
        """Version constraints with empty parts should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="cannot contain empty parts"):
            PluginPackageInfo(pypi_package="my-package", version_constraint=">=1.0.0,,")

    def test_version_constraint_too_long(self):
        """Version constraints exceeding 255 characters should be rejected."""
        from cpex.framework.models import PluginPackageInfo

        long_constraint = ">=1.0.0," + ",".join([f"!={i}.0.0" for i in range(100)])
        with pytest.raises(ValueError, match="exceeds maximum length of 255 characters"):
            PluginPackageInfo(pypi_package="my-package", version_constraint=long_constraint)

    def test_version_constraint_none_allowed(self):
        """None should be allowed for version_constraint."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package")
        assert pkg.version_constraint is None

    # -------------------------------------------------------------------------
    # Model Validator Tests
    # -------------------------------------------------------------------------

    def test_installation_method_required(self):
        """At least one installation method must be specified."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="At least one installation method must be specified"):
            PluginPackageInfo()

    def test_installation_method_pypi_only(self):
        """PyPI package alone should be valid."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package")
        assert pkg.pypi_package == "my-package"
        assert pkg.git_repository is None

    def test_installation_method_git_only(self):
        """Git repository alone should be valid."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(git_repository="https://github.com/user/repo.git")
        assert pkg.git_repository == "https://github.com/user/repo.git"
        assert pkg.pypi_package is None

    def test_installation_method_both_allowed(self):
        """Both PyPI package and Git repository can be specified."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package", git_repository="https://github.com/user/repo.git")
        assert pkg.pypi_package == "my-package"
        assert pkg.git_repository == "https://github.com/user/repo.git"

    def test_git_branch_requires_repository(self):
        """git_branch_tag_commit requires git_repository."""
        from cpex.framework.models import PluginPackageInfo

        with pytest.raises(ValueError, match="can only be specified when 'git_repository' is provided"):
            PluginPackageInfo(pypi_package="my-package", git_branch_tag_commit="main")

    def test_complete_git_installation(self):
        """Complete Git installation with all fields should be valid."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(
            git_repository="https://github.com/user/repo.git",
            git_branch_tag_commit="v1.0.0",
            version_constraint=">=1.0.0",
        )
        assert pkg.git_repository == "https://github.com/user/repo.git"
        assert pkg.git_branch_tag_commit == "v1.0.0"
        assert pkg.version_constraint == ">=1.0.0"

    def test_complete_pypi_installation(self):
        """Complete PyPI installation with version constraint should be valid."""
        from cpex.framework.models import PluginPackageInfo

        pkg = PluginPackageInfo(pypi_package="my-package", version_constraint=">=1.0.0,<2.0.0")
        assert pkg.pypi_package == "my-package"
        assert pkg.version_constraint == ">=1.0.0,<2.0.0"


# =============================================================================
# PluginVersionRegistry Tests
# =============================================================================


class TestPluginVersionRegistry:
    """Tests for PluginVersionRegistry class."""

    def test_get_version_returns_latest(self):
        """get_version should return the latest version."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        latest_version = PluginVersionInfo(
            version="2.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=latest_version, versions=[latest_version])

        assert registry.get_version() == latest_version

    def test_get_version_returns_none_when_no_latest(self):
        """get_version should return None when latest is not set."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        version = PluginVersionInfo(version="1.0.0", released="2024-01-01", manifest_file="manifest.json")

        registry = PluginVersionRegistry(latest=None, versions=[version])

        assert registry.get_version() is None

    def test_get_latest_compatible_finds_compatible_version(self):
        """get_latest_compatible should find a version compatible with the framework version."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.1.5",
        )
        v2 = PluginVersionInfo(
            version="2.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.5,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v2, versions=[v1, v2])

        # Framework version 0.1.3 should match v1
        result = registry.get_latest_compatible("0.1.3")
        assert result == v1

        # Framework version 0.1.8 should match v2
        result = registry.get_latest_compatible("0.1.8")
        assert result == v2

    def test_get_latest_compatible_returns_latest_when_multiple_match(self):
        """get_latest_compatible should return the latest version when multiple versions match."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v2 = PluginVersionInfo(
            version="1.5.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )
        v3 = PluginVersionInfo(
            version="2.0.0",
            released="2024-03-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v3, versions=[v1, v2, v3])

        # All versions support 0.1.5, should return the latest (v3)
        result = registry.get_latest_compatible("0.1.5")
        assert result == v3
        assert result.version == "2.0.0"

    def test_get_latest_compatible_returns_none_when_no_match(self):
        """get_latest_compatible should return None when no version is compatible."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.1.5",
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        # Framework version 0.2.0 is outside the range
        result = registry.get_latest_compatible("0.2.0")
        assert result is None

    def test_get_latest_compatible_handles_invalid_framework_version(self):
        """get_latest_compatible should return None for invalid framework version."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        # Invalid version format
        result = registry.get_latest_compatible("not-a-version")
        assert result is None

    def test_get_latest_compatible_skips_versions_without_min_max(self):
        """get_latest_compatible should skip versions without min_max_framework_version."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0", released="2024-01-01", manifest_file="manifest.json", min_max_framework_version=None
        )
        v2 = PluginVersionInfo(
            version="2.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v2, versions=[v1, v2])

        # Should only find v2 since v1 has no min_max_framework_version
        result = registry.get_latest_compatible("0.1.5")
        assert result == v2

    def test_get_latest_compatible_handles_malformed_min_max(self):
        """get_latest_compatible should skip versions with malformed min_max_framework_version."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0",  # Missing max version
        )
        v2 = PluginVersionInfo(
            version="2.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="invalid,version",  # Invalid versions
        )
        v3 = PluginVersionInfo(
            version="3.0.0",
            released="2024-03-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",  # Valid
        )

        registry = PluginVersionRegistry(latest=v3, versions=[v1, v2, v3])

        # Should only find v3
        result = registry.get_latest_compatible("0.1.5")
        assert result == v3

    def test_get_latest_compatible_with_prerelease_versions(self):
        """get_latest_compatible should handle pre-release versions correctly."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0rc1",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0.dev1,0.1.0.dev5",
        )
        v2 = PluginVersionInfo(
            version="1.0.0",
            released="2024-02-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v2, versions=[v1, v2])

        # Dev version should match v1
        result = registry.get_latest_compatible("0.1.0.dev3")
        assert result == v1

        # Stable version should match v2
        result = registry.get_latest_compatible("0.1.5")
        assert result == v2

    def test_get_latest_compatible_boundary_conditions(self):
        """get_latest_compatible should correctly handle boundary conditions."""
        from cpex.framework.models import PluginVersionInfo, PluginVersionRegistry

        v1 = PluginVersionInfo(
            version="1.0.0",
            released="2024-01-01",
            manifest_file="manifest.json",
            min_max_framework_version="0.1.0,0.2.0",
        )

        registry = PluginVersionRegistry(latest=v1, versions=[v1])

        # Exact min boundary
        result = registry.get_latest_compatible("0.1.0")
        assert result == v1

        # Exact max boundary
        result = registry.get_latest_compatible("0.2.0")
        assert result == v1

        # Just below min
        result = registry.get_latest_compatible("0.0.9")
        assert result is None

        # Just above max
        result = registry.get_latest_compatible("0.2.1")
        assert result is None

    def test_get_latest_compatible_with_empty_versions_list(self):
        """get_latest_compatible should return None when versions list is empty."""
        from cpex.framework.models import PluginVersionRegistry

        registry = PluginVersionRegistry(latest=None, versions=[])

        result = registry.get_latest_compatible("0.1.0")
        assert result is None
