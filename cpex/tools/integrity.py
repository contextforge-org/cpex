# -*- coding: utf-8 -*-
"""Location: ./cpex/tools/integrity.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Ted Habeck

Package integrity verification utilities.

This module provides SHA256 hash verification for downloaded packages
to ensure integrity beyond pip's built-in checks. It fetches expected
hashes from PyPI's JSON API and verifies downloaded files against them.

Features
────────
* SHA256 hash computation for package files
* PyPI JSON API integration for hash retrieval
* Configurable verification modes (strict/permissive)
* Detailed logging and error reporting

Typical usage
─────────────
```python
from cpex.tools.integrity import verify_package_integrity, fetch_pypi_package_hashes

# Fetch expected hashes from PyPI
hashes = fetch_pypi_package_hashes("requests", "2.31.0")

# Verify downloaded package
verify_package_integrity(Path("/tmp/requests-2.31.0.tar.gz"), hashes["sha256"])
```
"""

# Standard
import hashlib
import logging
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Constants
PYPI_JSON_API_URL = "https://pypi.org/pypi/{package}/json"
TEST_PYPI_JSON_API_URL = "https://test.pypi.org/pypi/{package}/json"
HASH_CHUNK_SIZE = 8192  # 8KB chunks for efficient file reading


class IntegrityVerificationError(Exception):
    """Raised when package integrity verification fails.

    This exception indicates that a downloaded package's hash does not
    match the expected hash from PyPI, suggesting potential tampering
    or corruption.

    Attributes:
        package_name: Name of the package that failed verification.
        expected_hash: The expected SHA256 hash from PyPI.
        actual_hash: The computed SHA256 hash of the downloaded file.
    """

    def __init__(self, package_name: str, expected_hash: str, actual_hash: str):
        """Initialize the exception with verification details.

        Args:
            package_name: Name of the package that failed verification.
            expected_hash: The expected SHA256 hash from PyPI.
            actual_hash: The computed SHA256 hash of the downloaded file.
        """
        self.package_name = package_name
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        super().__init__(
            f"Integrity verification failed for {package_name}: "
            f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
        )


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of a file.

    Reads the file in chunks to handle large files efficiently without
    loading the entire file into memory.

    Args:
        file_path: Path to the file to hash.
        algorithm: Hash algorithm to use (default: sha256).

    Returns:
        Hexadecimal hash string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the hash algorithm is not supported.

    Examples:
        >>> from pathlib import Path
        >>> import tempfile
        >>> with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        ...     _ = f.write("test content")
        ...     temp_path = Path(f.name)
        >>> hash_value = compute_file_hash(temp_path)
        >>> len(hash_value)
        64
        >>> temp_path.unlink()
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError as e:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from e

    with open(file_path, "rb") as f:
        while chunk := f.read(HASH_CHUNK_SIZE):
            hasher.update(chunk)

    hash_value = hasher.hexdigest()
    logger.debug("Computed %s hash for %s: %s", algorithm, file_path.name, hash_value[:16] + "...")
    return hash_value


def fetch_pypi_package_hashes(
    package_name: str, version: Optional[str] = None, use_test: bool = False, timeout: float = 30.0
) -> dict[str, dict[str, str]]:
    """Fetch package hashes from PyPI JSON API.

    Retrieves SHA256 hashes for all distribution files of a package version
    from PyPI's JSON API. If no version is specified, fetches hashes for
    the latest version.

    Args:
        package_name: Name of the package on PyPI.
        version: Specific version to fetch hashes for (optional).
        use_test: Whether to use test.pypi.org instead of pypi.org.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary mapping filename to hash information:
        {
            "package-1.0.0.tar.gz": {
                "sha256": "abc123...",
                "url": "https://files.pythonhosted.org/..."
            }
        }

    Raises:
        RuntimeError: If the API request fails or package is not found.

    Examples:
        >>> hashes = fetch_pypi_package_hashes("requests", "2.31.0")  # doctest: +SKIP
        >>> "requests-2.31.0.tar.gz" in hashes  # doctest: +SKIP
        True
    """
    api_url = TEST_PYPI_JSON_API_URL if use_test else PYPI_JSON_API_URL
    url = api_url.format(package=package_name)

    if version:
        url = f"{url.rstrip('/json')}/{version}/json"

    logger.debug("Fetching package hashes from: %s", url)

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise RuntimeError(f"Package '{package_name}' not found on {'test.' if use_test else ''}PyPI") from e
        raise RuntimeError(f"Failed to fetch package metadata: {e}") from e
    except httpx.RequestError as e:
        raise RuntimeError(f"Network error fetching package metadata: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error fetching package metadata: {e}") from e

    # Extract hashes from the response
    hashes = {}
    urls = data.get("urls", [])

    if not urls:
        logger.warning("No distribution files found for %s", package_name)
        return hashes

    for file_info in urls:
        filename = file_info.get("filename")
        digests = file_info.get("digests", {})
        sha256_hash = digests.get("sha256")
        file_url = file_info.get("url")

        if filename and sha256_hash:
            hashes[filename] = {"sha256": sha256_hash, "url": file_url}
            logger.debug("Found hash for %s: %s...", filename, sha256_hash[:16])

    logger.info("Fetched hashes for %d distribution files of %s", len(hashes), package_name)
    return hashes


def verify_package_integrity(
    file_path: Path, expected_hash: str, package_name: Optional[str] = None, strict: bool = True
) -> bool:
    """Verify package file integrity against expected SHA256 hash.

    Computes the SHA256 hash of the file and compares it to the expected
    hash. In strict mode, raises an exception on mismatch. In non-strict
    mode, logs a warning and returns False.

    Args:
        file_path: Path to the package file to verify.
        expected_hash: Expected SHA256 hash (hexadecimal string).
        package_name: Name of the package (for error messages).
        strict: If True, raise exception on mismatch. If False, return False.

    Returns:
        True if hash matches, False if mismatch in non-strict mode.

    Raises:
        IntegrityVerificationError: If hash doesn't match in strict mode.
        FileNotFoundError: If the file does not exist.

    Examples:
        >>> from pathlib import Path
        >>> import tempfile
        >>> with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        ...     _ = f.write("test")
        ...     temp_path = Path(f.name)
        >>> expected = compute_file_hash(temp_path)
        >>> verify_package_integrity(temp_path, expected, "test-pkg")
        True
        >>> temp_path.unlink()
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Package file not found: {file_path}")

    pkg_name = package_name or file_path.name
    logger.info("Verifying integrity of %s", pkg_name)

    actual_hash = compute_file_hash(file_path)

    if actual_hash.lower() == expected_hash.lower():
        logger.info("✓ Integrity verification passed for %s", pkg_name)
        return True

    error_msg = (
        f"Integrity verification failed for {pkg_name}\n"
        f"  Expected: {expected_hash}\n"
        f"  Actual:   {actual_hash}\n"
        f"  File:     {file_path}"
    )

    if strict:
        logger.error(error_msg)
        raise IntegrityVerificationError(pkg_name, expected_hash, actual_hash)

    logger.warning(error_msg)
    return False


def find_matching_hash(
    file_path: Path, hashes_dict: dict[str, dict[str, str]], package_name: Optional[str] = None
) -> Optional[str]:
    """Find the expected hash for a downloaded file from PyPI hashes dictionary.

    Matches the downloaded file against the hashes dictionary by filename.
    Handles various filename patterns including wheels and source distributions.

    Args:
        file_path: Path to the downloaded package file.
        hashes_dict: Dictionary of hashes from fetch_pypi_package_hashes().
        package_name: Name of the package (for logging).

    Returns:
        The expected SHA256 hash if found, None otherwise.

    Examples:
        >>> hashes = {"pkg-1.0.0.tar.gz": {"sha256": "abc123", "url": "..."}}
        >>> find_matching_hash(Path("/tmp/pkg-1.0.0.tar.gz"), hashes)
        'abc123'
    """
    filename = file_path.name
    pkg_name = package_name or filename

    if filename in hashes_dict:
        hash_value = hashes_dict[filename]["sha256"]
        logger.debug("Found matching hash for %s", filename)
        return hash_value

    # Try case-insensitive match
    for key, value in hashes_dict.items():
        if key.lower() == filename.lower():
            hash_value = value["sha256"]
            logger.debug("Found case-insensitive match for %s", filename)
            return hash_value

    logger.warning("No matching hash found for %s in PyPI metadata", pkg_name)
    return None

# Made with Bob
