# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/tools/test_integrity.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Unit tests for package integrity verification.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from cpex.tools.integrity import (
    IntegrityVerificationError,
    compute_file_hash,
    fetch_pypi_package_hashes,
    find_matching_hash,
    verify_package_integrity,
)


class TestComputeFileHash:
    """Tests for compute_file_hash function."""

    def test_compute_hash_basic(self, tmp_path):
        """Test basic hash computation."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        hash_value = compute_file_hash(test_file)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA256 produces 64 hex characters
        # Verify it's a valid hex string
        int(hash_value, 16)

    def test_compute_hash_consistency(self, tmp_path):
        """Test that same content produces same hash."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("consistent content")

        hash1 = compute_file_hash(test_file)
        hash2 = compute_file_hash(test_file)

        assert hash1 == hash2

    def test_compute_hash_different_content(self, tmp_path):
        """Test that different content produces different hashes."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("content 1")
        file2.write_text("content 2")

        hash1 = compute_file_hash(file1)
        hash2 = compute_file_hash(file2)

        assert hash1 != hash2

    def test_compute_hash_large_file(self, tmp_path):
        """Test hash computation for large files (chunked reading)."""
        test_file = tmp_path / "large.txt"
        # Create a file larger than chunk size (8KB)
        test_file.write_text("x" * 10000)

        hash_value = compute_file_hash(test_file)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64

    def test_compute_hash_binary_file(self, tmp_path):
        """Test hash computation for binary files."""
        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        hash_value = compute_file_hash(test_file)

        assert isinstance(hash_value, str)
        assert len(hash_value) == 64

    def test_compute_hash_nonexistent_file(self, tmp_path):
        """Test that nonexistent file raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError, match="File not found"):
            compute_file_hash(nonexistent)

    def test_compute_hash_unsupported_algorithm(self, tmp_path):
        """Test that unsupported algorithm raises ValueError."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_file_hash(test_file, algorithm="invalid_algo")


class TestFetchPyPiPackageHashes:
    """Tests for fetch_pypi_package_hashes function."""

    @patch("cpex.tools.integrity.httpx.Client")
    def test_fetch_hashes_success(self, mock_client_class):
        """Test successful hash fetching from PyPI."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "urls": [
                {
                    "filename": "package-1.0.0.tar.gz",
                    "digests": {"sha256": "abc123def456"},
                    "url": "https://files.pythonhosted.org/package-1.0.0.tar.gz",
                },
                {
                    "filename": "package-1.0.0-py3-none-any.whl",
                    "digests": {"sha256": "789ghi012jkl"},
                    "url": "https://files.pythonhosted.org/package-1.0.0-py3-none-any.whl",
                },
            ]
        }
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        hashes = fetch_pypi_package_hashes("test-package", "1.0.0")

        assert len(hashes) == 2
        assert "package-1.0.0.tar.gz" in hashes
        assert hashes["package-1.0.0.tar.gz"]["sha256"] == "abc123def456"
        assert "package-1.0.0-py3-none-any.whl" in hashes
        assert hashes["package-1.0.0-py3-none-any.whl"]["sha256"] == "789ghi012jkl"

    @patch("cpex.tools.integrity.httpx.Client")
    def test_fetch_hashes_test_pypi(self, mock_client_class):
        """Test fetching from test.pypi.org."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"urls": []}
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        fetch_pypi_package_hashes("test-package", use_test=True)

        # Verify test PyPI URL was used
        call_args = mock_client.get.call_args[0][0]
        assert "test.pypi.org" in call_args

    @patch("cpex.tools.integrity.httpx.Client")
    def test_fetch_hashes_package_not_found(self, mock_client_class):
        """Test handling of 404 response."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client.get.return_value = mock_response
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=mock_response
        )
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        with pytest.raises(RuntimeError, match="Package .* not found"):
            fetch_pypi_package_hashes("nonexistent-package")

    @patch("cpex.tools.integrity.httpx.Client")
    def test_fetch_hashes_network_error(self, mock_client_class):
        """Test handling of network errors."""
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.RequestError("Connection failed")
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        with pytest.raises(RuntimeError, match="Network error"):
            fetch_pypi_package_hashes("test-package")

    @patch("cpex.tools.integrity.httpx.Client")
    def test_fetch_hashes_no_urls(self, mock_client_class):
        """Test handling of package with no distribution files."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"urls": []}
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        hashes = fetch_pypi_package_hashes("empty-package")

        assert hashes == {}

    @patch("cpex.tools.integrity.httpx.Client")
    def test_fetch_hashes_missing_sha256(self, mock_client_class):
        """Test handling of files without SHA256 digests."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "urls": [
                {
                    "filename": "package-1.0.0.tar.gz",
                    "digests": {},  # No SHA256
                    "url": "https://files.pythonhosted.org/package-1.0.0.tar.gz",
                }
            ]
        }
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        hashes = fetch_pypi_package_hashes("test-package")

        assert hashes == {}


class TestVerifyPackageIntegrity:
    """Tests for verify_package_integrity function."""

    def test_verify_success(self, tmp_path):
        """Test successful verification."""
        test_file = tmp_path / "package.tar.gz"
        test_file.write_text("package content")

        expected_hash = compute_file_hash(test_file)
        result = verify_package_integrity(test_file, expected_hash, "test-package")

        assert result is True

    def test_verify_failure_strict(self, tmp_path):
        """Test verification failure in strict mode."""
        test_file = tmp_path / "package.tar.gz"
        test_file.write_text("package content")

        wrong_hash = "0" * 64

        with pytest.raises(IntegrityVerificationError) as exc_info:
            verify_package_integrity(test_file, wrong_hash, "test-package", strict=True)

        assert "test-package" in str(exc_info.value)
        assert exc_info.value.package_name == "test-package"
        assert exc_info.value.expected_hash == wrong_hash

    def test_verify_failure_non_strict(self, tmp_path):
        """Test verification failure in non-strict mode."""
        test_file = tmp_path / "package.tar.gz"
        test_file.write_text("package content")

        wrong_hash = "0" * 64

        result = verify_package_integrity(test_file, wrong_hash, "test-package", strict=False)

        assert result is False

    def test_verify_case_insensitive(self, tmp_path):
        """Test that hash comparison is case-insensitive."""
        test_file = tmp_path / "package.tar.gz"
        test_file.write_text("package content")

        expected_hash = compute_file_hash(test_file)
        uppercase_hash = expected_hash.upper()

        result = verify_package_integrity(test_file, uppercase_hash, "test-package")

        assert result is True

    def test_verify_nonexistent_file(self, tmp_path):
        """Test verification of nonexistent file."""
        nonexistent = tmp_path / "nonexistent.tar.gz"

        with pytest.raises(FileNotFoundError, match="Package file not found"):
            verify_package_integrity(nonexistent, "abc123", "test-package")

    def test_verify_without_package_name(self, tmp_path):
        """Test verification without explicit package name."""
        test_file = tmp_path / "package.tar.gz"
        test_file.write_text("package content")

        expected_hash = compute_file_hash(test_file)
        result = verify_package_integrity(test_file, expected_hash)

        assert result is True


class TestFindMatchingHash:
    """Tests for find_matching_hash function."""

    def test_find_exact_match(self, tmp_path):
        """Test finding exact filename match."""
        test_file = tmp_path / "package-1.0.0.tar.gz"
        hashes = {
            "package-1.0.0.tar.gz": {"sha256": "abc123", "url": "https://example.com"},
            "other-file.whl": {"sha256": "def456", "url": "https://example.com"},
        }

        result = find_matching_hash(test_file, hashes)

        assert result == "abc123"

    def test_find_case_insensitive_match(self, tmp_path):
        """Test finding case-insensitive match."""
        test_file = tmp_path / "Package-1.0.0.TAR.GZ"
        hashes = {"package-1.0.0.tar.gz": {"sha256": "abc123", "url": "https://example.com"}}

        result = find_matching_hash(test_file, hashes)

        assert result == "abc123"

    def test_find_no_match(self, tmp_path):
        """Test when no matching hash is found."""
        test_file = tmp_path / "unknown-package.tar.gz"
        hashes = {"other-package.tar.gz": {"sha256": "abc123", "url": "https://example.com"}}

        result = find_matching_hash(test_file, hashes)

        assert result is None

    def test_find_empty_hashes(self, tmp_path):
        """Test with empty hashes dictionary."""
        test_file = tmp_path / "package.tar.gz"
        hashes = {}

        result = find_matching_hash(test_file, hashes)

        assert result is None


class TestIntegrityVerificationError:
    """Tests for IntegrityVerificationError exception."""

    def test_error_attributes(self):
        """Test that error has correct attributes."""
        error = IntegrityVerificationError("test-pkg", "expected123", "actual456")

        assert error.package_name == "test-pkg"
        assert error.expected_hash == "expected123"
        assert error.actual_hash == "actual456"
        assert "test-pkg" in str(error)
        assert "expected123" in str(error)
        assert "actual456" in str(error)

    def test_error_message_format(self):
        """Test error message formatting."""
        error = IntegrityVerificationError("my-package", "a" * 64, "b" * 64)

        message = str(error)
        assert "my-package" in message
        assert "Integrity verification failed" in message
        # Should show truncated hashes
        assert "aaaaaaaaaaaaaaa" in message
        assert "bbbbbbbbbbbbbbb" in message


class TestIntegrationScenarios:
    """Integration tests for complete verification workflows."""

    @patch("cpex.tools.integrity.httpx.Client")
    def test_full_verification_workflow(self, mock_client_class, tmp_path):
        """Test complete workflow: fetch hashes, download, verify."""
        # Setup mock PyPI response
        test_file = tmp_path / "package-1.0.0.tar.gz"
        test_file.write_text("package content")
        actual_hash = compute_file_hash(test_file)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "urls": [
                {
                    "filename": "package-1.0.0.tar.gz",
                    "digests": {"sha256": actual_hash},
                    "url": "https://files.pythonhosted.org/package-1.0.0.tar.gz",
                }
            ]
        }
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        # Fetch hashes
        hashes = fetch_pypi_package_hashes("package", "1.0.0")

        # Find matching hash
        expected_hash = find_matching_hash(test_file, hashes)

        # Verify
        result = verify_package_integrity(test_file, expected_hash, "package")

        assert result is True

    @patch("cpex.tools.integrity.httpx.Client")
    def test_verification_with_tampered_package(self, mock_client_class, tmp_path):
        """Test detection of tampered package."""
        # Setup mock with original hash
        original_hash = "abc123def456" + "0" * 52

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "urls": [
                {
                    "filename": "package-1.0.0.tar.gz",
                    "digests": {"sha256": original_hash},
                    "url": "https://files.pythonhosted.org/package-1.0.0.tar.gz",
                }
            ]
        }
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client_class.return_value = mock_client

        # Create "tampered" file with different content
        test_file = tmp_path / "package-1.0.0.tar.gz"
        test_file.write_text("tampered content")

        # Fetch hashes
        hashes = fetch_pypi_package_hashes("package", "1.0.0")
        expected_hash = find_matching_hash(test_file, hashes)

        # Verification should fail
        with pytest.raises(IntegrityVerificationError):
            verify_package_integrity(test_file, expected_hash, "package", strict=True)

# Made with Bob
