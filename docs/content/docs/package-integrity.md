---
title: "Package Integrity Verification"
weight: 150
---

# Package Integrity Verification

The CPEX framework includes built-in SHA256 hash verification for packages, providing an additional security layer beyond pip's built-in checks.

## Overview

The framework provides integrity verification for different installation sources:

### PyPI Packages

When installing plugins from PyPI, the framework automatically:

1. Fetches expected SHA256 hashes from PyPI's JSON API
2. Downloads the package file
3. Computes the SHA256 hash of the downloaded file
4. Compares the computed hash against the expected hash
5. Aborts installation if hashes don't match

### Git and Monorepo Packages

When installing from Git repositories or monorepos, the framework:

1. Downloads the package archive
2. Computes the SHA256 hash of the downloaded file
3. Logs the hash for future reference and verification
4. Allows manual verification against known-good hashes

This protects against:
- **Tampered packages**: Detects if a package has been modified in transit
- **Corrupted downloads**: Identifies incomplete or corrupted downloads
- **Supply chain attacks**: Verifies package authenticity

## Configuration

### Environment Variables

Control integrity verification behavior using environment variables:

```bash
# Enable/disable integrity verification (default: true)
export PLUGINS_VERIFY_PACKAGE_INTEGRITY=true

# Strict mode: fail if hashes unavailable (default: false)
export PLUGINS_STRICT_INTEGRITY_MODE=false
```

### Configuration File

Add to your `.env` file:

```ini
# Package Integrity Verification
PLUGINS_VERIFY_PACKAGE_INTEGRITY=true
PLUGINS_STRICT_INTEGRITY_MODE=false
```

## Verification Modes

### Standard Mode (Default)

```bash
PLUGINS_VERIFY_PACKAGE_INTEGRITY=true
PLUGINS_STRICT_INTEGRITY_MODE=false
```

**Behavior:**
- Verifies packages when hashes are available
- Warns but continues if hashes are unavailable
- Fails immediately on hash mismatch

**Use case:** Recommended for most deployments. Provides security without breaking installations for packages that don't publish hashes.

### Strict Mode

```bash
PLUGINS_VERIFY_PACKAGE_INTEGRITY=true
PLUGINS_STRICT_INTEGRITY_MODE=true
```

**Behavior:**
- Requires hashes for all packages
- Fails installation if hashes are unavailable
- Fails immediately on hash mismatch

**Use case:** High-security environments where all packages must be verifiable.

### Disabled Mode

```bash
PLUGINS_VERIFY_PACKAGE_INTEGRITY=false
```

**Behavior:**
- Skips hash verification entirely
- Relies only on pip's built-in checks

**Use case:** Development environments or when troubleshooting installation issues.

## Usage Examples

### Installing with Verification (Default)

**PyPI Installation:**
```bash
# Verification is enabled by default
cpex plugin install --type pypi my-plugin

# Output shows verification status:
# Package integrity verification: enabled
# Fetching package hashes from PyPI for my-plugin
# Retrieved hashes for 2 distribution files
# Verifying integrity of my-plugin-1.0.0.tar.gz
# ✓ Integrity verification passed for my-plugin
```

**Git Installation:**
```bash
# Hash is computed and logged for future verification
cpex plugin install --type git "MyPlugin @ git+https://github.com/user/repo.git"

# Output shows:
# Package integrity verification: enabled (hash will be computed and logged)
# Package integrity hash for MyPlugin (MyPlugin-1.0.0.tar.gz): SHA256=abc123def456...
# Store this hash for future verification or to detect tampering
```

**Monorepo Installation:**
```bash
# Hash is computed and logged
cpex plugin install --type monorepo my-plugin

# Output shows:
# Package integrity hash for my-plugin (my-plugin-1.0.0.tar.gz): SHA256=abc123def456...
# Store this hash for future verification or to detect tampering
```

### Installing with Verification Disabled

```bash
# Temporarily disable verification
export PLUGINS_VERIFY_PACKAGE_INTEGRITY=false
cpex plugin install --type pypi my-plugin

# Output shows:
# Package integrity verification: disabled
```

### Installing from Test PyPI

```bash
# Verification works with test.pypi.org too
cpex plugin install --type test-pypi my-test-plugin
```

## Error Handling

### Hash Mismatch

If a downloaded package's hash doesn't match the expected hash:

```
ERROR: Integrity verification failed for my-plugin
  Expected: abc123def456...
  Actual:   789ghi012jkl...
  File:     /tmp/cpex_plugin_my-plugin_xyz/my-plugin-1.0.0.tar.gz

IntegrityVerificationError: Integrity verification failed for my-plugin
```

**Resolution:**
1. Retry the installation (may be a transient network issue)
2. Check if PyPI is experiencing issues
3. Report to package maintainer if problem persists

### Hash Unavailable

If PyPI doesn't provide hashes for a package:

**Standard Mode:**
```
WARNING: No hashes available from PyPI for my-plugin
WARNING: No matching hash found for my-plugin-1.0.0.tar.gz. Proceeding without verification.
```
Installation continues.

**Strict Mode:**
```
ERROR: No hashes available from PyPI for my-plugin
RuntimeError: Package hashes required in strict mode but not available
```
Installation fails.

### Network Error Fetching Hashes

If the PyPI API is unreachable:

```
WARNING: Failed to fetch hashes from PyPI: Connection timeout. Proceeding without verification.
```

Installation continues to avoid breaking deployments due to temporary network issues.

## Security Best Practices

### Production Deployments

1. **Enable verification** (default setting)
2. **Monitor logs** for verification warnings
3. **Consider strict mode** for critical environments
4. **Use private PyPI mirrors** with known-good packages

### Development Environments

1. **Keep verification enabled** to catch issues early
2. **Use standard mode** for flexibility
3. **Disable only when troubleshooting** specific issues

### CI/CD Pipelines

1. **Enable verification** in all pipelines
2. **Use strict mode** for production deployments
3. **Cache verified packages** to reduce API calls
4. **Fail builds** on verification errors

## Technical Details

### Hash Algorithm

- **Algorithm**: SHA256 (256-bit)
- **Source**: PyPI JSON API (`/pypi/{package}/json`)
- **Format**: Hexadecimal string (64 characters)

### Verification Process

```python
# 1. Fetch expected hashes from PyPI
hashes = fetch_pypi_package_hashes("my-plugin", "1.0.0")
# Returns: {"my-plugin-1.0.0.tar.gz": {"sha256": "abc123...", "url": "..."}}

# 2. Download package
package_file = download_package("my-plugin==1.0.0")

# 3. Compute actual hash
actual_hash = compute_file_hash(package_file)

# 4. Verify
if actual_hash != expected_hash:
    raise IntegrityVerificationError(...)
```

### Performance Impact

- **API Call**: ~100-500ms to fetch hashes from PyPI
- **Hash Computation**: ~10-50ms per MB of package size
- **Total Overhead**: Typically <1 second per package

The overhead is minimal compared to download time and provides significant security benefits.

## Troubleshooting

### Verification Always Fails

**Symptoms:** Every package fails verification with hash mismatch.

**Possible Causes:**
1. Corporate proxy modifying downloads
2. Antivirus scanning altering files
3. Disk corruption

**Solutions:**
1. Check proxy configuration
2. Temporarily disable antivirus
3. Run disk check utility

### Verification Warnings for All Packages

**Symptoms:** "No hashes available" warning for every package.

**Possible Causes:**
1. Network blocking PyPI API
2. Firewall rules
3. PyPI API outage

**Solutions:**
1. Check network connectivity to `pypi.org`
2. Review firewall rules
3. Check PyPI status page

### Slow Installations

**Symptoms:** Package installations take much longer than expected.

**Possible Causes:**
1. Slow network to PyPI API
2. Large packages taking time to hash

**Solutions:**
1. Use a PyPI mirror closer to your location
2. Consider caching verified packages
3. This is normal for very large packages (>100MB)

## API Reference

See [`cpex.tools.integrity`](../api-reference/#cpextoolsintegrity) for detailed API documentation.

## Related Documentation

- [CLI Reference](../cli/) - Command-line usage
- [Configuration](../configuration/) - General configuration options
- [Security Best Practices](../security/) - Comprehensive security guide

## Changelog

### Version 0.1.0rc1
- Initial implementation of SHA256 hash verification
- Support for PyPI and Test PyPI
- Configurable verification modes (standard/strict/disabled)
- Comprehensive error handling and logging